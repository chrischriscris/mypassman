//! Vault state: an unlocked key bundle + device key + record index built by
//! replaying verified op logs. Decrypt-on-demand: the index holds sealed
//! `fields_ct`; `item()` opens the inner layer only when asked.

use crate::error::{CoreError, Result};
use crate::item::{tag, Item, ItemKind};
use crate::manifest::Manifest;
use crate::op::{Gossip, Op, OpPlaintext, OpType};
use crate::{DEVICE_ID_LEN, HASH_LEN, RECORD_ID_LEN};
use mpm_crypto::keys::{DeviceKey, KeyBundle};
use std::collections::BTreeMap;

/// Index entry — everything a DEK-holder may see without opening k_rec.
#[derive(Debug, Clone)]
pub struct RecordSummary {
    pub record_id: [u8; RECORD_ID_LEN],
    pub kind: Option<ItemKind>,
    pub name: String,
    pub created: u64,
    pub hlc: u64,
    pub tombstoned: bool,
    fields_ct: Vec<u8>,
}

pub struct Vault {
    pub manifest: Manifest,
    bundle: KeyBundle,
    device: DeviceKey,
    next_seq: u64,
    head: [u8; HASH_LEN],
    records: BTreeMap<[u8; RECORD_ID_LEN], RecordSummary>,
}

pub fn now_hlc() -> u64 {
    // v0: wall-clock millis. True HLC (counter + causal max) lands with sync.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Vault {
    pub fn new(manifest: Manifest, bundle: KeyBundle, device: DeviceKey) -> Result<Self> {
        // Anchor authenticity: the manifest must be signed by the owner key
        // inside this bundle — not merely self-consistent.
        if manifest.owner_vk != bundle.owner_verifying_key() {
            return Err(CoreError::BadManifestSig);
        }
        let entry = manifest.device(&device.id).ok_or(CoreError::NotEnrolled)?;
        if !entry.active {
            return Err(CoreError::NotEnrolled);
        }
        // Our private key must actually produce the enrolled pubkey —
        // otherwise we'd sign ops that fail verification everywhere else.
        if entry.vk != device.verifying_key() {
            return Err(CoreError::NotEnrolled);
        }
        Ok(Self {
            manifest,
            bundle,
            device,
            next_seq: 1,
            head: [0u8; HASH_LEN],
            records: BTreeMap::new(),
        })
    }

    /// Verify + apply one stored op from this device's log. Enforces seq
    /// order, chain linkage, signature, and AEAD integrity.
    pub fn apply_own_op(&mut self, op: &Op) -> Result<()> {
        if op.seq != self.next_seq {
            return Err(CoreError::ChainBreak(op.seq));
        }
        let vk = self
            .manifest
            .device(&self.device.id)
            .ok_or(CoreError::NotEnrolled)?
            .vk;
        let pt = op.open(
            &vk,
            &self.bundle.dek,
            &self.manifest.vault_id,
            self.manifest.key_epoch,
            &self.device.id,
        )?;
        if pt.prev_op_hash != self.head {
            return Err(CoreError::ChainBreak(op.seq));
        }
        self.head = op.hash();
        self.next_seq += 1;
        self.apply_pt(pt);
        Ok(())
    }

    /// Replay a FOREIGN device log (sync path): verifies each op's signature
    /// against the registry and its internal chain. Returns ops for merge.
    pub fn verify_foreign_log(
        &self,
        device_id: &[u8; DEVICE_ID_LEN],
        ops: &[Op],
    ) -> Result<Vec<OpPlaintext>> {
        let entry = self.manifest.device(device_id).ok_or(CoreError::NotEnrolled)?;
        let mut head = [0u8; HASH_LEN];
        let mut out = Vec::with_capacity(ops.len());
        for (i, op) in ops.iter().enumerate() {
            if op.seq != i as u64 + 1 {
                return Err(CoreError::ChainBreak(op.seq));
            }
            let pt = op.open(
                &entry.vk,
                &self.bundle.dek,
                &self.manifest.vault_id,
                self.manifest.key_epoch,
                device_id,
            )?;
            if pt.prev_op_hash != head {
                return Err(CoreError::ChainBreak(op.seq));
            }
            head = op.hash();
            out.push(pt);
        }
        Ok(out)
    }

    /// Merge already-verified foreign ops into the index (max-HLC wins;
    /// preserved-loser conflict versions land with sync UI at M3).
    pub fn apply_foreign(&mut self, pts: Vec<OpPlaintext>) {
        for pt in pts {
            self.apply_pt(pt);
        }
    }

    fn apply_pt(&mut self, pt: OpPlaintext) {
        let e = self.records.entry(pt.record_id).or_insert_with(|| RecordSummary {
            record_id: pt.record_id,
            kind: None,
            name: String::new(),
            created: pt.created,
            hlc: 0,
            tombstoned: false,
            fields_ct: Vec::new(),
        });
        // Later HLC wins; equal HLC → deterministic (applied order).
        if pt.hlc >= e.hlc {
            match pt.op_type {
                OpType::Upsert => {
                    e.kind = pt.kind;
                    e.name = String::from_utf8_lossy(&pt.name).into_owned();
                    e.hlc = pt.hlc;
                    e.tombstoned = false;
                    e.fields_ct = pt.fields_ct;
                }
                OpType::Tombstone => {
                    e.hlc = pt.hlc;
                    e.tombstoned = true;
                    e.fields_ct.clear();
                }
                OpType::Meta => {}
            }
        }
    }

    /// Current gossip observation of every known device log — embedded in
    /// each new op so any reader can detect rollback/equivocation later.
    fn gossip(&self) -> Vec<Gossip> {
        // v0 single-device: we only observe ourselves. Multi-device merge
        // lands with sync (M3) — the field is wired, the vector fills then.
        vec![Gossip { device_id: self.device.id, seq: self.next_seq - 1, head: self.head }]
    }

    /// Seal + sign an upsert op. Caller persists via store::append_op.
    pub fn make_upsert(&mut self, kind: ItemKind, mut item: Item) -> Result<(Op, [u8; RECORD_ID_LEN])> {
        let mut record_id = [0u8; RECORD_ID_LEN];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut record_id);

        let name = item
            .get(tag::NAME)
            .map(|v| v.to_vec())
            .unwrap_or_default();
        item.fields.remove(&tag::NAME); // name lives in the outer layer only

        let fields_ct = OpPlaintext::seal_fields(
            &self.bundle.dek,
            &self.manifest.vault_id,
            self.manifest.key_epoch,
            &record_id,
            &item,
        )?;

        let now = now_hlc();
        let pt = OpPlaintext {
            prev_op_hash: self.head,
            hlc: now,
            op_type: OpType::Upsert,
            record_id,
            kind: Some(kind),
            schema_v: 1,
            created: now,
            name,
            fields_ct,
            gossip: self.gossip(),
        };
        let op = Op::seal(&pt, self.next_seq, &self.bundle.dek, &self.manifest.vault_id, self.manifest.key_epoch, &self.device)?;
        Ok((op, record_id))
    }

    /// Seal + sign a tombstone op for `record_id`.
    pub fn make_tombstone(&mut self, record_id: &[u8; RECORD_ID_LEN]) -> Result<Op> {
        let pt = OpPlaintext {
            prev_op_hash: self.head,
            hlc: now_hlc(),
            op_type: OpType::Tombstone,
            record_id: *record_id,
            kind: None,
            schema_v: 1,
            created: 0,
            name: Vec::new(),
            fields_ct: Vec::new(),
            gossip: self.gossip(),
        };
        Op::seal(&pt, self.next_seq, &self.bundle.dek, &self.manifest.vault_id, self.manifest.key_epoch, &self.device)
    }

    /// Commit a freshly-made op to the in-memory index (call after store
    /// durably writes it).
    pub fn commit(&mut self, op: &Op) -> Result<()> {
        self.apply_own_op(op)
    }

    /// Open a record's secret fields — decrypt-on-demand boundary.
    pub fn item(&self, record_id: &[u8; RECORD_ID_LEN]) -> Result<Item> {
        let rec = self.records.get(record_id).ok_or(CoreError::NotFound)?;
        if rec.tombstoned || rec.fields_ct.is_empty() {
            return Err(CoreError::NotFound);
        }
        let pt = OpPlaintext {
            prev_op_hash: [0u8; 32],
            hlc: rec.hlc,
            op_type: OpType::Upsert,
            record_id: rec.record_id,
            kind: rec.kind,
            schema_v: 1,
            created: rec.created,
            name: rec.name.as_bytes().to_vec(),
            fields_ct: rec.fields_ct.clone(),
            gossip: Vec::new(),
        };
        pt.open_fields(&self.bundle.dek, &self.manifest.vault_id, self.manifest.key_epoch)
    }

    pub fn records(&self) -> impl Iterator<Item = &RecordSummary> {
        self.records.values().filter(|r| !r.tombstoned)
    }

    pub fn find(&self, name_or_id: &str) -> Option<[u8; RECORD_ID_LEN]> {
        // exact id (hex) first, then case-insensitive name match
        if let Ok(b) = hex_decode(name_or_id) {
            if b.len() == RECORD_ID_LEN && self.records.contains_key(b.as_slice()) {
                let mut id = [0u8; 16];
                id.copy_from_slice(&b);
                if self.records.get(&id).map(|r| !r.tombstoned).unwrap_or(false) {
                    return Some(id);
                }
            }
        }
        let needle = name_or_id.to_lowercase();
        let mut hits: Vec<[u8; 16]> = self
            .records()
            .filter(|r| r.name.to_lowercase().contains(&needle))
            .map(|r| r.record_id)
            .collect();
        if hits.len() == 1 {
            Some(hits.pop().unwrap())
        } else {
            None
        }
    }

    pub fn dek(&self) -> &[u8; 32] {
        &self.bundle.dek
    }

    pub fn bundle(&self) -> &KeyBundle {
        &self.bundle
    }

    pub fn device_id(&self) -> &[u8; DEVICE_ID_LEN] {
        &self.device.id
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CoreError::NotFound);
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect())
}
