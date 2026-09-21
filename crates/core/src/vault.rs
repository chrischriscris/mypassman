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

/// Outcome of a best-effort foreign-log verification (`verify_foreign_prefix`):
/// the verified prefix plus the first failure, so callers can keep good ops
/// and quarantine the rest instead of wedging on one bad frame.
pub struct ForeignVerify {
    /// Plaintexts verified in order, up to (not including) the first failure.
    pub pts: Vec<OpPlaintext>,
    /// `(seq, error)` of the first op that failed, if any.
    pub failed_at: Option<(u64, CoreError)>,
    /// `(seq, op hash)` at the end of the verified prefix.
    pub tip: (u64, [u8; HASH_LEN]),
}

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
    /// key_epoch the winning op was sealed under — picks the DEK in `item()`.
    key_epoch: u32,
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
        let entry = self
            .manifest
            .device(&self.device.id)
            .ok_or(CoreError::NotEnrolled)?;
        // A revoked device's own ops past its horizon are untrusted too —
        // this blocks new writes on a revoked device outright.
        if !entry.active && op.seq > entry.revoked_seq.unwrap_or(0) {
            return Err(CoreError::RevokedWrite(op.seq));
        }
        let vk = entry.vk;
        let pt = self.open_op(op, &vk, &self.device.id)?;
        if pt.prev_op_hash != self.head {
            return Err(CoreError::ChainBreak(op.seq));
        }
        self.head = op.hash();
        self.next_seq += 1;
        self.apply_pt(pt);
        Ok(())
    }

    /// Epoch new ops must be sealed under. If the manifest moved past the
    /// bundle (keys rotated while this unlock was open), writing at the old
    /// epoch would leak to anyone holding the old DEK — refuse instead.
    fn write_epoch(&self) -> Result<u32> {
        let e = self.manifest.key_epoch;
        if self.bundle.current_epoch() != e || self.bundle.dek_at(e).is_none() {
            return Err(CoreError::KeysRotated(e));
        }
        Ok(e)
    }

    /// Open an op trying each DEK epoch — logs span a rotation boundary:
    /// ops written pre-rotation open under the old epoch, new ones under the
    /// current. `hint` is the last epoch that worked for this log (ops are
    /// appended sequentially, so the epoch flips at most once per log).
    fn open_op_hinted(
        &self,
        op: &Op,
        vk: &[u8; 32],
        device_id: &[u8; DEVICE_ID_LEN],
        hint: u32,
    ) -> Result<OpPlaintext> {
        let mut first_err = None;
        for epoch in
            std::iter::once(hint).chain(self.bundle.epochs_desc().filter(move |e| *e != hint))
        {
            let Some(dek) = self.bundle.dek_at(epoch) else {
                continue;
            };
            match op.open(
                vk,
                dek,
                &self.manifest.vault_id,
                self.manifest.format_v,
                epoch,
                device_id,
            ) {
                Ok(pt) => return Ok(pt),
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        Err(first_err.unwrap_or(CoreError::Crypto(mpm_crypto::CryptoError::BadKey)))
    }

    fn open_op(
        &self,
        op: &Op,
        vk: &[u8; 32],
        device_id: &[u8; DEVICE_ID_LEN],
    ) -> Result<OpPlaintext> {
        self.open_op_hinted(op, vk, device_id, self.manifest.key_epoch)
    }

    /// Replay a FOREIGN device log (sync path): verifies each op's signature
    /// against the registry and its internal chain. Returns ops for merge.
    /// Strict: any failure errors the whole log. Callers that must stay
    /// usable on corrupt/compromised foreign logs should use
    /// `verify_foreign_prefix` and quarantine instead.
    pub fn verify_foreign_log(
        &self,
        device_id: &[u8; DEVICE_ID_LEN],
        ops: &[Op],
    ) -> Result<Vec<OpPlaintext>> {
        self.verify_foreign_from(device_id, ops, 1, [0u8; HASH_LEN])
    }

    /// Verify a SUFFIX of a foreign log: ops starting at `first_seq`
    /// chained onto `prev_head` (the hash of the last op we already
    /// verified — zero hash for a fresh log). Lets a live daemon merge
    /// sync-pulled ops without re-verifying the whole log.
    /// Strict: any failure errors the whole log.
    pub fn verify_foreign_from(
        &self,
        device_id: &[u8; DEVICE_ID_LEN],
        ops: &[Op],
        first_seq: u64,
        prev_head: [u8; HASH_LEN],
    ) -> Result<Vec<OpPlaintext>> {
        let r = self.verify_foreign_prefix(device_id, ops, first_seq, prev_head);
        match r.failed_at {
            Some((_, e)) => Err(e),
            None => Ok(r.pts),
        }
    }

    /// Best-effort foreign verification: returns the verified prefix plus
    /// the first failure (if any). Ops after a revoked device's
    /// `revoked_seq` horizon surface as `RevokedWrite`. Callers keep the
    /// prefix and quarantine the rest — a compromised device's validly
    /// signed garbage must not wedge unlock or block revocation.
    pub fn verify_foreign_prefix(
        &self,
        device_id: &[u8; DEVICE_ID_LEN],
        ops: &[Op],
        first_seq: u64,
        prev_head: [u8; HASH_LEN],
    ) -> ForeignVerify {
        let mut out = Vec::with_capacity(ops.len());
        let mut tip = (first_seq.saturating_sub(1), prev_head);
        let Some(entry) = self.manifest.device(device_id) else {
            return ForeignVerify {
                pts: out,
                failed_at: Some((first_seq, CoreError::NotEnrolled)),
                tip,
            };
        };
        // Trust horizon: active devices are unbounded; revoked devices keep
        // only ops they wrote while still trusted.
        let horizon = if entry.active {
            u64::MAX
        } else {
            entry.revoked_seq.unwrap_or(0)
        };
        let mut head = prev_head;
        let mut epoch_hint = self.manifest.key_epoch;
        for (i, op) in ops.iter().enumerate() {
            let expected = first_seq + i as u64;
            let mut fail = |e: CoreError| ForeignVerify {
                pts: std::mem::take(&mut out),
                failed_at: Some((op.seq, e)),
                tip,
            };
            if op.seq != expected {
                return fail(CoreError::ChainBreak(op.seq));
            }
            if op.seq > horizon {
                return fail(CoreError::RevokedWrite(op.seq));
            }
            match self.open_op_hinted(op, &entry.vk, device_id, epoch_hint) {
                Ok(pt) if pt.prev_op_hash == head => {
                    head = op.hash();
                    tip = (op.seq, head);
                    epoch_hint = pt.key_epoch;
                    out.push(pt);
                }
                Ok(_) => return fail(CoreError::ChainBreak(op.seq)),
                Err(e) => return fail(e),
            }
        }
        ForeignVerify {
            pts: out,
            failed_at: None,
            tip,
        }
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
                key_epoch: 0,
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
                    e.key_epoch = pt.key_epoch;
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

        let epoch = self.write_epoch()?;
        let fields_ct = OpPlaintext::seal_fields(
            self.bundle.dek(),
            &self.manifest.vault_id,
            epoch,
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
            key_epoch: epoch,
        };
        Op::seal(
            &pt,
            self.next_seq,
            self.bundle.dek(),
            &self.manifest.vault_id,
            self.manifest.format_v,
            epoch,
            &self.device,
        )
    }

    /// Seal + sign a tombstone op for `record_id`.
    pub fn make_tombstone(&mut self, record_id: &[u8; RECORD_ID_LEN]) -> Result<Op> {
        let epoch = self.write_epoch()?;
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
            key_epoch: epoch,
        };
        Op::seal(
            &pt,
            self.next_seq,
            self.bundle.dek(),
            &self.manifest.vault_id,
            self.manifest.format_v,
            epoch,
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
            key_epoch: rec.key_epoch,
        };
        let dek = self
            .bundle
            .dek_at(rec.key_epoch)
            .ok_or(CoreError::Crypto(mpm_crypto::CryptoError::BadKey))?;
        pt.open_fields(dek, &self.manifest.vault_id)
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
        self.bundle.dek()
    }

    /// Rotate the DEK: fresh epoch key, manifest.key_epoch follows in
    /// lockstep. Caller re-wraps every slot and re-signs — ops already
    /// sealed stay readable via DEK history. Pair with a password change
    /// or a revoked device can just re-derive the same KEK.
    pub fn rotate_keys(&mut self) -> u32 {
        let epoch = self.bundle.rotate();
        self.manifest.key_epoch = epoch;
        epoch
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
