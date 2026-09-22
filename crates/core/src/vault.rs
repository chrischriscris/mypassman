//! Vault state: an unlocked key bundle + device key + record index built by
//! replaying verified op logs. Decrypt-on-demand: the index holds sealed
//! `fields_ct`; `item()` opens the inner layer only when asked.

use crate::aad;
use crate::error::{CoreError, Result};
use crate::item::{tag, Item, ItemKind};
use crate::manifest::Manifest;
use crate::op::{Gossip, Op, OpPlaintext, OpType, Snapshot};
use crate::{DEVICE_ID_LEN, HASH_LEN, RECORD_ID_LEN};
use ed25519_dalek::{Signature, Signer};
use mpm_crypto::aead::{self, NONCE_LEN};
use mpm_crypto::keys::{DeviceKey, KeyBundle};
use mpm_crypto::subkey;
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
    /// Adopted snapshot's covered vector: (device → seq, head hash). Chain
    /// anchors for logs whose covered prefixes were dropped — replay and
    /// sync verify suffixes against these instead of genesis.
    anchors: BTreeMap<[u8; DEVICE_ID_LEN], (u64, [u8; HASH_LEN])>,
    /// The snapshot currently adopted as replay base — its winner frames
    /// are where covered ops' bytes live after the logs were compacted.
    adopted: Option<Snapshot>,
    /// LWW losers worth preserving as conflict copies. Enqueued during
    /// merge (either direction: incoming-loses or winner-displaces), then
    /// drained by `materialize_conflicts` once the index is final —
    /// content compare happens against the FINAL winner, so the conflict
    /// set is replay-order-independent.
    pending_conflicts: Vec<ConflictLoser>,
    /// Highest origin_seq each device has stated per record. Distinguishes
    /// "lost a concurrent race" (this device said nothing newer — real
    /// conflict) from "superseded by its own later write" (plain history —
    /// preserving it would materialize every old version as a conflict).
    last_by_dev: BTreeMap<([u8; RECORD_ID_LEN], [u8; DEVICE_ID_LEN]), u64>,
}

/// A merge loser that may hold data the winner doesn't — enough of its
/// op to rebuild the copy without keeping the frame.
#[derive(Clone, Debug)]
pub struct ConflictLoser {
    pub record_id: [u8; RECORD_ID_LEN],
    pub kind: Option<ItemKind>,
    pub name: Vec<u8>,
    pub created: u64,
    pub fields_ct: Vec<u8>,
    pub key_epoch: u32,
    pub origin: ([u8; DEVICE_ID_LEN], u64),
}

/// Deterministic conflict-copy record id: every replica derives the same
/// target for the same losing op, so independently materialized copies
/// dedup into one record.
pub fn derive_conflict_id(
    record_id: &[u8; RECORD_ID_LEN],
    origin_device: &[u8; DEVICE_ID_LEN],
    origin_seq: u64,
) -> [u8; RECORD_ID_LEN] {
    let mut h = blake3::Hasher::new();
    h.update(b"mypassman/v1/conflict");
    h.update(record_id);
    h.update(origin_device);
    h.update(&origin_seq.to_le_bytes());
    let mut id = [0u8; RECORD_ID_LEN];
    id.copy_from_slice(&h.finalize().as_bytes()[..RECORD_ID_LEN]);
    id
}

/// Wall-clock millis — metadata only (e.g. `enrolled_at`). Op ordering
/// uses `Vault::next_hlc`, which is monotone against observed ops.
pub fn now_hlc() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// How far past wall-clock an observed op may push our local HLC clock.
/// Merge ordering still uses each op's true `hlc` — this bound only caps
/// what `apply_pt` feeds into `max_hlc`, so an enrolled device cannot pin
/// local timestamps at saturation (e.g. `u64::MAX`) with a single op.
/// 24h is generous for real clock drift yet bounded enough that even a
/// malicious value stops affecting `next_hlc` within a day of wall time.
const MAX_HLC_SKEW_MS: u64 = 24 * 60 * 60 * 1000;

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
            anchors: BTreeMap::new(),
            adopted: None,
            pending_conflicts: Vec::new(),
            last_by_dev: BTreeMap::new(),
        })
    }

    /// Chain anchor for a device log under the adopted snapshot — replay
    /// of a compacted log starts at `covered+1` with `prev = covered head`.
    /// None when no snapshot covers the device (verify from genesis).
    pub fn anchor(&self, dev: &[u8; DEVICE_ID_LEN]) -> Option<(u64, [u8; HASH_LEN])> {
        self.anchors.get(dev).copied()
    }

    /// Clear all replayed state — records, chain position, snapshot anchors.
    /// Used by the daemon to rebuild after an on-disk change (compaction,
    /// restore) without re-running key derivation.
    pub fn reset(&mut self) {
        self.next_seq = 1;
        self.head = [0u8; HASH_LEN];
        self.max_hlc = 0;
        self.records.clear();
        self.anchors.clear();
        self.adopted = None;
        self.pending_conflicts.clear();
        self.last_by_dev.clear();
    }

    /// The snapshot this vault's index is currently seeded from, if any.
    pub fn adopted_snapshot(&self) -> Option<&Snapshot> {
        self.adopted.as_ref()
    }

    /// Whether any device's log has a compacted (dropped) prefix — i.e.
    /// replay is anchored mid-chain rather than at genesis.
    pub fn has_compacted(&self) -> bool {
        !self.anchors.is_empty()
    }

    /// Verify + decode a checkpoint op frame pulled from a snapshot file or
    /// observed mid-replay: device signature, author enrolled and within
    /// its trust horizon, outer AEAD. Returns the snapshot payload.
    pub fn open_snapshot_op(&self, op: &Op, author: &[u8; DEVICE_ID_LEN]) -> Result<Snapshot> {
        let entry = self.manifest.device(author).ok_or(CoreError::NotEnrolled)?;
        let horizon = if entry.active {
            u64::MAX
        } else {
            entry.revoked_seq.unwrap_or(0)
        };
        if op.seq > horizon {
            return Err(CoreError::RevokedWrite(op.seq));
        }
        let pt = self.open_op_hinted(op, &entry.vk, author, self.manifest.key_epoch)?;
        if pt.op_type != OpType::Checkpoint {
            return Err(CoreError::BadSnapshot("op is not a checkpoint"));
        }
        pt.snapshot
            .ok_or(CoreError::BadSnapshot("empty checkpoint"))
    }

    /// Adopt a verified snapshot as the replay base: seed the index from
    /// its winner frames and record the covered vector as chain anchors.
    /// Returns the winner plaintexts (they're covered ops — callers feeding
    /// `check_snapshot_claim` need them in the pts set).
    /// Own-chain position is NOT seeded here — `apply_own_anchor` after
    /// confirming the on-disk log actually starts past the anchor.
    pub fn adopt_snapshot(&mut self, snap: &Snapshot) -> Result<Vec<OpPlaintext>> {
        for g in &snap.covered {
            self.anchors.insert(g.device_id, (g.seq, g.head));
        }
        self.adopted = Some(snap.clone());
        let mut pts = Vec::with_capacity(snap.winners.len());
        for (dev, op) in &snap.winners {
            let vk = self.manifest.device(dev).ok_or(CoreError::NotEnrolled)?.vk;
            let pt = self.open_op_hinted(op, &vk, dev, self.manifest.key_epoch)?;
            self.apply_pt(pt.clone());
            pts.push(pt);
        }
        Ok(pts)
    }

    /// Attest that THIS frame's claim passed verify-or-nothing on an
    /// unlocked replica — owner-signed over the frame hash, so the proof
    /// is durable (survives backup/restore under a fresh device key) and
    /// unforgeable by anyone who can only write files in the vault dir.
    /// The author of a checkpoint self-attests: it computed the winners
    /// from its own verified replay, which IS the claim check.
    pub fn attest_snapshot(&self, frame: &Op) -> [u8; 64] {
        self.bundle
            .owner_signing_key()
            .sign(&aad::snapshot_ok(&self.manifest.vault_id, &frame.hash()))
            .to_bytes()
    }

    /// Whether `att` is a valid claim attestation for THIS exact frame
    /// under this vault's owner key.
    pub fn snapshot_attested(&self, frame: &Op, att: &[u8; 64]) -> bool {
        mpm_crypto::keys::verify(
            &self.manifest.owner_vk,
            &aad::snapshot_ok(&self.manifest.vault_id, &frame.hash()),
            &Signature::from_bytes(att),
        )
        .is_ok()
    }

    /// Continue our own chain from the adopted anchor — call only when the
    /// on-disk log's first op is `anchor_seq + 1` (i.e. the covered prefix
    /// was physically dropped). If the log still starts at genesis, replay
    /// it whole instead.
    pub fn apply_own_anchor(&mut self) {
        if let Some(&(seq, head)) = self.anchors.get(&self.device.id) {
            self.next_seq = seq + 1;
            self.head = head;
        }
    }

    /// Check a candidate checkpoint against locally replayed state.
    /// `tips`: per-device verified (seq, head). `pts`: every verified op
    /// plaintext this replay produced (snapshot winners included if a prior
    /// snapshot seeded us — they replay as ordinary ops).
    ///
    /// Adoption is verify-or-nothing: every covered device must be at-or-
    /// past its claimed head with a provable hash link, and the claimed
    /// winner set must equal the winners we compute over the covered ops.
    /// Anything less and the checkpoint is ignored — compaction is only
    /// ever a cache, never an authority.
    pub fn check_snapshot_claim(
        &self,
        snap: &Snapshot,
        tips: &BTreeMap<[u8; DEVICE_ID_LEN], (u64, [u8; HASH_LEN])>,
        pts: &[OpPlaintext],
    ) -> Result<()> {
        // hash at covered seq: tip hash when covered == tip, else the
        // prev_op_hash of the op at covered+1 (chain link), else an
        // already-adopted anchor (deeper coverage is pre-verified).
        let hash_at = |dev: &[u8; DEVICE_ID_LEN], seq: u64| -> Option<[u8; HASH_LEN]> {
            if let Some(&(tseq, thead)) = tips.get(dev) {
                if tseq == seq {
                    return Some(thead);
                }
                if tseq > seq {
                    return pts
                        .iter()
                        .find(|p| p.origin_device == *dev && p.origin_seq == seq + 1)
                        .map(|p| p.prev_op_hash);
                }
            }
            self.anchors
                .get(dev)
                .and_then(|&(aseq, ahead)| (aseq == seq).then_some(ahead))
        };
        for g in &snap.covered {
            match hash_at(&g.device_id, g.seq) {
                Some(h) if h == g.head => {}
                _ => return Err(CoreError::BadSnapshot("covered head unverified")),
            }
        }
        // Claimed winners must be covered, authentic, and exactly the set
        // we'd compute by replaying the covered ops ourselves.
        let mut claimed: BTreeMap<[u8; RECORD_ID_LEN], ([u8; DEVICE_ID_LEN], u64)> =
            BTreeMap::new();
        let covered_of = |dev: &[u8; DEVICE_ID_LEN]| -> u64 {
            snap.covered
                .iter()
                .find(|g| g.device_id == *dev)
                .map(|g| g.seq)
                .unwrap_or(0)
        };
        for (dev, op) in &snap.winners {
            if op.seq > covered_of(dev) {
                return Err(CoreError::BadSnapshot("winner beyond covered seq"));
            }
            let vk = self.manifest.device(dev).ok_or(CoreError::NotEnrolled)?.vk;
            let pt = self.open_op_hinted(op, &vk, dev, self.manifest.key_epoch)?;
            claimed.insert(pt.record_id, (*dev, op.seq));
        }
        let mut computed: BTreeMap<[u8; RECORD_ID_LEN], (u64, [u8; DEVICE_ID_LEN], u64)> =
            BTreeMap::new();
        for p in pts {
            if p.origin_seq > covered_of(&p.origin_device) {
                continue; // post-horizon op — not part of this cut
            }
            if !matches!(p.op_type, OpType::Upsert | OpType::Tombstone) {
                continue;
            }
            let e = computed
                .entry(p.record_id)
                .or_insert((p.hlc, p.origin_device, p.origin_seq));
            if (p.hlc, p.origin_device, p.origin_seq) >= *e {
                *e = (p.hlc, p.origin_device, p.origin_seq);
            }
        }
        for (rid, (dev, seq)) in &claimed {
            match computed.get(rid) {
                Some(&(_, d, s)) if d == *dev && s == *seq => {}
                _ => return Err(CoreError::BadSnapshot("winner set mismatch")),
            }
        }
        if computed.len() != claimed.len() {
            return Err(CoreError::BadSnapshot("winner set mismatch"));
        }
        Ok(())
    }

    /// Seal + sign a checkpoint op covering `covered` device heads with
    /// `winners` as the materialized state. The op sits in our own log at
    /// the next seq — vector entries must be strictly below it for us.
    pub fn make_checkpoint(
        &mut self,
        covered: Vec<Gossip>,
        winners: Vec<([u8; DEVICE_ID_LEN], Op)>,
    ) -> Result<Op> {
        let epoch = self.write_epoch()?;
        let pt = OpPlaintext {
            prev_op_hash: self.head,
            hlc: self.next_hlc(),
            op_type: OpType::Checkpoint,
            record_id: [0u8; RECORD_ID_LEN],
            kind: None,
            schema_v: 1,
            created: 0,
            name: Vec::new(),
            fields_ct: Vec::new(),
            gossip: self.gossip(),
            snapshot: Some(Snapshot { covered, winners }),
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

    /// Monotone timestamp: wall clock, but never below max observed + 1.
    /// A clock that stepped backwards must not produce tombstones/upserts
    /// that lose to older ops on HLC comparison.
    pub fn next_hlc(&self) -> u64 {
        now_hlc().max(self.max_hlc.saturating_add(1))
    }

    /// Verify + apply one stored op from this device's log. Enforces seq
    /// order, chain linkage, signature, and AEAD integrity. Returns the
    /// verified plaintext (callers that replay collect it for snapshot
    /// adoption checks).
    pub fn apply_own_op(&mut self, op: &Op) -> Result<OpPlaintext> {
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
        self.apply_pt(pt.clone());
        Ok(pt)
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
    pub fn apply_foreign(&mut self, pts: &[OpPlaintext]) {
        for pt in pts {
            self.apply_pt(pt.clone());
        }
    }

    /// Winner (device, seq) of every tracked record, tombstones included —
    /// what a checkpoint must carry so covered ops can be dropped.
    pub fn winner_origins(&self) -> Vec<([u8; DEVICE_ID_LEN], u64)> {
        self.records.values().map(|r| r.origin).collect()
    }

    fn apply_pt(&mut self, pt: OpPlaintext) {
        // Absorb into the local clock only up to the skew bound — merge
        // ordering below still compares the op's true hlc, so clamping
        // changes nothing consensus-visible while keeping a saturated or
        // far-future value from pinning `next_hlc`.
        self.max_hlc = self
            .max_hlc
            .max(pt.hlc.min(now_hlc().saturating_add(MAX_HLC_SKEW_MS)));
        // Only record ops touch the index — checkpoints/meta/unknown ops
        // still advance the HLC clock and chain, nothing else.
        if !matches!(pt.op_type, OpType::Upsert | OpType::Tombstone) {
            return;
        }
        let k = (pt.record_id, pt.origin_device);
        let last = self.last_by_dev.entry(k).or_insert(0);
        *last = (*last).max(pt.origin_seq);
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
        let genesis = ([0u8; DEVICE_ID_LEN], 0);
        let mut displaced = None;
        if (pt.hlc, pt.origin_device, pt.origin_seq) >= (e.hlc, e.origin.0, e.origin.1) {
            // An upsert winner displaces the previous upsert winner: that
            // loser may carry data the new winner lacks — queue it as a
            // conflict candidate (content compare defers to materialize).
            if e.origin != genesis && e.origin != (pt.origin_device, pt.origin_seq) && !e.tombstoned
            {
                displaced = Some(ConflictLoser {
                    record_id: e.record_id,
                    kind: e.kind,
                    name: e.name.clone().into_bytes(),
                    created: e.created,
                    fields_ct: e.fields_ct.clone(),
                    key_epoch: e.key_epoch,
                    origin: e.origin,
                });
            }
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
                _ => {}
            }
        } else if pt.op_type == OpType::Upsert {
            // Incoming upsert loses to the standing winner (incl. a
            // tombstone — its fields would vanish otherwise).
            displaced = Some(ConflictLoser {
                record_id: pt.record_id,
                kind: pt.kind,
                name: pt.name,
                created: pt.created,
                fields_ct: pt.fields_ct,
                key_epoch: pt.key_epoch,
                origin: (pt.origin_device, pt.origin_seq),
            });
        }
        if let Some(l) = displaced {
            self.queue_conflict(l);
        }
    }

    fn queue_conflict(&mut self, l: ConflictLoser) {
        if !self
            .pending_conflicts
            .iter()
            .any(|p| p.record_id == l.record_id && p.origin == l.origin)
        {
            self.pending_conflicts.push(l);
        }
    }

    /// Conflict candidates found since last drain — callers that can
    /// append ops should `materialize_conflicts` instead of reading this.
    pub fn has_pending_conflicts(&self) -> bool {
        !self.pending_conflicts.is_empty()
    }

    /// Turn one pending LWW loser into a real conflict-copy upsert — call
    /// in a loop, persisting + committing each op before the next (head
    /// and seq only advance on commit). Runs only after replay is
    /// complete so the compare sees FINAL winners:
    /// - loser fields == winner fields → silent drop (duplicate edit)
    /// - conflict rid already exists (live or tombstoned) → already
    ///   materialized (or deliberately deleted — stays gone)
    /// - otherwise: `name (conflict, <device>)` sealed under the derived
    ///   record id's k_rec, signed by THIS device — a normal op that
    ///   syncs, survives compaction, and degrades to a regular item on
    ///   older clients.
    pub fn materialize_conflict(&mut self) -> Result<Option<(Op, [u8; RECORD_ID_LEN])>> {
        while let Some(l) = self.pending_conflicts.pop() {
            let rid2 = derive_conflict_id(&l.record_id, &l.origin.0, l.origin.1);
            if self.records.contains_key(&rid2) {
                continue;
            }
            // the losing device itself wrote a newer op for this record —
            // superseded history, not a concurrent edit
            if self
                .last_by_dev
                .get(&(l.record_id, l.origin.0))
                .copied()
                .unwrap_or(0)
                > l.origin.1
            {
                continue;
            }
            if let Some(w) = self.records.get(&l.record_id) {
                // identical name + identical decrypted fields → the "loss"
                // was a duplicate edit, nothing to preserve. A winner that
                // won't open counts as different — preserve, don't guess.
                let identical = !w.tombstoned
                    && w.name.as_bytes() == l.name.as_slice()
                    && self
                        .open_fields_blob(&l.record_id, w.key_epoch, &w.fields_ct)
                        .and_then(|wi| {
                            self.open_fields_blob(&l.record_id, l.key_epoch, &l.fields_ct)
                                .map(|li| wi.fields == li.fields)
                        })
                        .unwrap_or(false);
                if identical {
                    continue;
                }
            }
            // a loser whose inner seal won't open has nothing to preserve
            let Ok(item) = self.open_fields_blob(&l.record_id, l.key_epoch, &l.fields_ct) else {
                continue;
            };
            let dev_label = self
                .manifest
                .device(&l.origin.0)
                .map(|d| d.name.clone())
                .unwrap_or_else(|| l.origin.0[..4].iter().map(|b| format!("{b:02x}")).collect());
            let name = format!(
                "{} (conflict, {})",
                String::from_utf8_lossy(&l.name),
                dev_label
            );
            let epoch = self.write_epoch()?;
            let fields_ct = OpPlaintext::seal_fields(
                self.bundle.dek(),
                &self.manifest.vault_id,
                epoch,
                &rid2,
                &item,
            )?;
            let pt = OpPlaintext {
                prev_op_hash: self.head,
                hlc: self.next_hlc(),
                op_type: OpType::Upsert,
                record_id: rid2,
                kind: l.kind,
                schema_v: 1,
                created: l.created,
                name: name.into_bytes(),
                fields_ct,
                gossip: self.gossip(),
                snapshot: None,
                origin_device: self.device.id,
                origin_seq: self.next_seq,
                key_epoch: epoch,
            };
            let op = Op::seal(
                &pt,
                self.next_seq,
                self.bundle.dek(),
                &self.manifest.vault_id,
                self.manifest.format_v,
                epoch,
                &self.device,
            )?;
            return Ok(Some((op, rid2)));
        }
        Ok(None)
    }

    fn open_fields_blob(
        &self,
        record_id: &[u8; RECORD_ID_LEN],
        key_epoch: u32,
        blob: &[u8],
    ) -> Result<Item> {
        if blob.len() < NONCE_LEN + aead::TAG_LEN {
            return Err(CoreError::Tlv("fields_ct short"));
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let k_rec = subkey::derive_record_key(self.bundle.dek(), record_id);
        let pt = aead::open(
            &k_rec,
            nonce.try_into().unwrap(),
            &crate::aad::record_fields(&self.manifest.vault_id, record_id, key_epoch),
            ct,
        )?;
        Item::decode(&pt)
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
            snapshot: None,
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
            snapshot: None,
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
        self.apply_own_op(op).map(|_| ())
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
            snapshot: None,
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
