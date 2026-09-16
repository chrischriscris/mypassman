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
    /// (device_id, seq) of the op that last won this record — the tiebreak
    /// that makes equal-HLC merges order-independent.
    origin: ([u8; DEVICE_ID_LEN], u64),
}

pub struct Vault {
    pub manifest: Manifest,
    bundle: KeyBundle,
    device: DeviceKey,
    next_seq: u64,
    head: [u8; HASH_LEN],
    max_hlc: u64,
    records: BTreeMap<[u8; RECORD_ID_LEN], RecordSummary>,
}

/// Wall-clock millis — metadata only (e.g. `enrolled_at`). Op ordering
/// uses `Vault::next_hlc`, which is monotone against observed ops.
pub fn now_hlc() -> u64 {
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
            max_hlc: 0,
            records: BTreeMap::new(),
        })
    }

    /// Monotone timestamp: wall clock, but never below max observed + 1.
    /// A clock that stepped backwards must not produce tombstones/upserts
    /// that lose to older ops on HLC comparison.
    pub fn next_hlc(&self) -> u64 {
        now_hlc().max(self.max_hlc.saturating_add(1))
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
            self.manifest.format_v,
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
        let entry = self
            .manifest
            .device(device_id)
            .ok_or(CoreError::NotEnrolled)?;
        if !entry.active {
            return Err(CoreError::NotEnrolled); // revoked devices don't merge
        }
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
                self.manifest.format_v,
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
        self.max_hlc = self.max_hlc.max(pt.hlc);
        let e = self
            .records
            .entry(pt.record_id)
            .or_insert_with(|| RecordSummary {
                record_id: pt.record_id,
                kind: None,
                name: String::new(),
                created: pt.created,
                hlc: 0,
                tombstoned: false,
                fields_ct: Vec::new(),
                origin: ([0u8; DEVICE_ID_LEN], 0),
            });
        // Total order (hlc, origin_device, origin_seq): the merge result
        // depends only on the op SET, never on replay/scan order.
        if (pt.hlc, pt.origin_device, pt.origin_seq) >= (e.hlc, e.origin.0, e.origin.1) {
            match pt.op_type {
                OpType::Upsert => {
                    e.kind = pt.kind;
                    e.name = String::from_utf8_lossy(&pt.name).into_owned();
                    e.hlc = pt.hlc;
                    e.tombstoned = false;
                    e.fields_ct = pt.fields_ct;
                    e.origin = (pt.origin_device, pt.origin_seq);
                }
                OpType::Tombstone => {
                    e.hlc = pt.hlc;
                    e.tombstoned = true;
                    e.fields_ct.clear();
                    e.origin = (pt.origin_device, pt.origin_seq);
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
        vec![Gossip {
            device_id: self.device.id,
            seq: self.next_seq - 1,
            head: self.head,
        }]
    }

    /// Seal + sign an upsert op. Caller persists via store::append_op.
    pub fn make_upsert(&mut self, kind: ItemKind, item: Item) -> Result<(Op, [u8; RECORD_ID_LEN])> {
        let mut record_id = [0u8; RECORD_ID_LEN];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut record_id);
        let op = self.make_upsert_for(record_id, kind, item)?;
        Ok((op, record_id))
    }

    /// Upsert into an EXISTING record (edit): same record_id, new hlc,
    /// original `created` preserved. History lives in the op chain.
    pub fn make_update(
        &mut self,
        record_id: &[u8; RECORD_ID_LEN],
        kind: ItemKind,
        item: Item,
    ) -> Result<Op> {
        self.make_upsert_for(*record_id, kind, item)
    }

    fn make_upsert_for(
        &mut self,
        record_id: [u8; RECORD_ID_LEN],
        kind: ItemKind,
        mut item: Item,
    ) -> Result<Op> {
        let name = item.get(tag::NAME).map(|v| v.to_vec()).unwrap_or_default();
        item.fields.remove(&tag::NAME); // name lives in the outer layer only

        let fields_ct = OpPlaintext::seal_fields(
            &self.bundle.dek,
            &self.manifest.vault_id,
            self.manifest.key_epoch,
            &record_id,
            &item,
        )?;

        let now = self.next_hlc();
        let created = self
            .records
            .get(&record_id)
            .map(|r| r.created)
            .unwrap_or(now);
        let pt = OpPlaintext {
            prev_op_hash: self.head,
            hlc: now,
            op_type: OpType::Upsert,
            record_id,
            kind: Some(kind),
            schema_v: 1,
            created,
            name,
            fields_ct,
            gossip: self.gossip(),
            origin_device: self.device.id,
            origin_seq: self.next_seq,
        };
        Op::seal(
            &pt,
            self.next_seq,
            &self.bundle.dek,
            &self.manifest.vault_id,
            self.manifest.format_v,
            self.manifest.key_epoch,
            &self.device,
        )
    }

    /// Seal + sign a tombstone op for `record_id`.
    pub fn make_tombstone(&mut self, record_id: &[u8; RECORD_ID_LEN]) -> Result<Op> {
        let pt = OpPlaintext {
            prev_op_hash: self.head,
            hlc: self.next_hlc(),
            op_type: OpType::Tombstone,
            record_id: *record_id,
            kind: None,
            schema_v: 1,
            created: 0,
            name: Vec::new(),
            fields_ct: Vec::new(),
            gossip: self.gossip(),
            origin_device: self.device.id,
            origin_seq: self.next_seq,
        };
        Op::seal(
            &pt,
            self.next_seq,
            &self.bundle.dek,
            &self.manifest.vault_id,
            self.manifest.format_v,
            self.manifest.key_epoch,
            &self.device,
        )
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
            origin_device: [0u8; 16],
            origin_seq: 0,
        };
        pt.open_fields(
            &self.bundle.dek,
            &self.manifest.vault_id,
            self.manifest.key_epoch,
        )
    }

    pub fn records(&self) -> impl Iterator<Item = &RecordSummary> {
        self.records.values().filter(|r| !r.tombstoned)
    }

    /// Resolution order: exact record-id hex → exact name (case-insensitive)
    /// → unique substring. Returns `Err` for ambiguous or known-but-tombstoned.
    pub fn find(&self, name_or_id: &str) -> FindResult {
        // exact id (hex)
        if let Ok(b) = hex_decode(name_or_id) {
            if b.len() == RECORD_ID_LEN && self.records.contains_key(b.as_slice()) {
                let mut id = [0u8; 16];
                id.copy_from_slice(&b);
                return match self.records.get(&id) {
                    Some(r) if !r.tombstoned => FindResult::One(id),
                    Some(_) => FindResult::Tombstoned,
                    None => FindResult::None,
                };
            }
        }
        let needle = name_or_id.to_lowercase();
        // exact name wins over substring hits
        for r in self.records() {
            if r.name.eq_ignore_ascii_case(name_or_id) {
                return FindResult::One(r.record_id);
            }
        }
        let hits: Vec<[u8; 16]> = self
            .records()
            .filter(|r| r.name.to_lowercase().contains(&needle))
            .map(|r| r.record_id)
            .collect();
        match hits.len() {
            0 => FindResult::None,
            1 => FindResult::One(hits[0]),
            _ => FindResult::Ambiguous(hits.len()),
        }
    }

    /// Last verified op-chain tip + its seq (for checkpoint persistence).
    pub fn head(&self) -> (u64, [u8; HASH_LEN]) {
        (self.next_seq - 1, self.head)
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

    pub fn device(&self) -> &DeviceKey {
        &self.device
    }
}

/// Outcome of a `find()` lookup — distinguishes "not there" from "ambiguous"
/// from "was deleted" so callers can message honestly.
#[derive(Debug)]
pub enum FindResult {
    One([u8; RECORD_ID_LEN]),
    None,
    /// Record exists but is tombstoned (matched by exact id only).
    Tombstoned,
    Ambiguous(usize),
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
