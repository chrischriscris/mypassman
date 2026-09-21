# mypassman vault format v1

Normative reference for the on-disk vault layout. All multi-byte integers
little-endian. `||` = concatenation. Code: `crates/core` (format),
`crates/store` (I/O), `crates/crypto` (primitives).

## Vault directory

```
<vault>/
  MANIFEST                 owner_sig(64) || manifest TLV body
  ops/<device_id_hex>.log  append-only op frames, one log per device
  snapshots/               adopted compaction state (post-compaction; may be empty)
    <author_device>.snap   raw checkpoint op frame (sealed + signed like any op)
    base.vec               adopted covered vector: (device_id, seq, head) triples
```

Outside the vault dir, per device (platform local data dir,
`$MPM_DATA` override):

```
devices/<vault_id_hex>.<device_id_hex>   device_id(16) || ed25519 seed(32), mode 0600
sync/<vault_id_hex>.json                 relay url + tokens, mode 0600
checkpoints/<vault_id_hex>.ckpt          device-signed last-verified head
```

## Keys

| Key | Derivation | Purpose |
|---|---|---|
| KEK | Argon2id(master_pw, salt, m/t/p from manifest) | unwraps key bundle |
| KeyBundle | random; wrapped per wrap-slot | {dek, record_key seed, owner signing key, …} |
| k_rec | per-record subkey `derive_record_key(dek, record_id)` | encrypts `fields_ct` |
| device sk | random ed25519 seed, stored 0600 | signs ops + checkpoints |
| owner sk | inside KeyBundle | signs manifest |

Argon2id: version 0x13, params (`m_kib`, `t`, `p`) + 32-byte salt stored
in the manifest KDF field and per-wrap-slot. AEAD is XChaCha20-Poly1305
(24-byte nonces) throughout.

## MANIFEST

```
file = owner_sig(64) || body
body = TLV fields in canonical tag order (unknown tags preserved verbatim)
```

TLV field: `tag(u8) || len(u32) || value`.

| tag | field | value |
|---|---|---|
| 0x01 | vault_id | 16 bytes |
| 0x02 | format_version | u16 |
| 0x03 | min_reader_version | u16 |
| 0x04 | kdf | m_kib u32, t u32, p u32, salt 32 |
| 0x05 | wrap_slot | nested TLV (below) — repeatable |
| 0x06 | key_epoch | u32 |
| 0x07 | snapshot_epoch | u64 — the manifest revision; bumped on EVERY owner-signed write (device add/revoke, wrap-slot change), so a replayed older manifest always loses |
| 0x08 | device | nested TLV (below) — repeatable |
| 0x09 | purged_before_epoch | u64 |
| 0x0A | owner_vk | ed25519 verifying key, 32 bytes |

Wrap slot (0x05):

| tag | field | value |
|---|---|---|
| 0x01 | slot_type | 1=password, 2=recovery, 3=biometric marker |
| 0x02 | salt | 32 bytes (absent for biometric marker) |
| 0x03 | m_kib | u32 |
| 0x04 | t | u32 |
| 0x05 | p | u32 |
| 0x06 | blob | wrapped KeyBundle ciphertext |

Device entry (0x08):

| tag | field | value |
|---|---|---|
| 0x01 | device_id | 16 bytes |
| 0x02 | vk | ed25519 verifying key, 32 bytes |
| 0x03 | name | utf-8 |
| 0x04 | status | u8: 1=active, 2=revoked |
| 0x05 | enrolled_at | u64 (hlc) |
| 0x06 | revoked_seq | u64, optional — revocation horizon: when status=2, ops with `seq <= revoked_seq` still verify and merge (they were written while the device was trusted); later seqs are rejected. Absent on an inactive device means "revoked before horizons" — nothing merges |

`owner_sig` = ed25519 sign(owner_sk, body). Readers MUST verify before
trusting any field. Unknown tags are retained and re-encoded so
forward-compatible fields survive round-trips.

## Op frame (`ops/<device>.log` and on the wire)

```
frame = seq(8) || nonce(24) || sig(64) || ct_len(4) || ct
```

- `seq` — per-device monotone counter, starting at 1, gap-free.
- `sig` — ed25519 sign(device_sk, `"mypassman/v1/opsig" || seq || nonce || ct`)
- `ct` — XChaCha20-Poly1305(dek, nonce, OpPlaintext-TLV),
  aad = `aad::op(vault_id, format_v, key_epoch, device_id, seq)` — binds the
  frame to its vault, key epoch, device, and position.

OpPlaintext TLV (`ct` decrypts to):

| tag | field |
|---|---|
| 0x01 | prev_op_hash (32) — hash chain within this device's log |
| 0x02 | hlc (u64) |
| 0x03 | type (u8): 1=Upsert, 2=Tombstone, 3=Meta, 4=Checkpoint |
| 0x04 | record_id (16) |
| 0x05 | kind |
| 0x06 | schema_v |
| 0x07 | created (u64) |
| 0x08 | fields_ct — nonce(24)‖XChaCha20-Poly1305(k_rec, fields TLV); empty for tombstone/meta/checkpoint |
| 0x09 | gossip — vector of observed foreign heads |
| 0x0A | name — display name (UTF-8). Inside the DEK-encrypted op plaintext but
outside the k_rec field seal — index-visible to vault members without
opening per-record secrets |
| 0x0B | snapshot — nested TLV (below); present only on type=4 |

Unknown type bytes (>4) MUST decode as an opaque `Unknown(u8)`: they
chain-verify (signature + prev_op_hash still checked), carry no merge
effect, and never wedge older readers. New op kinds can therefore ship
without breaking deployed clients.

Snapshot TLV (0x0B):

| tag | field | value |
|---|---|---|
| 0x01 | covered | repeated gossip triples: device_id(16) ‖ seq(8) ‖ head_hash(32) — one per device log this checkpoint claims to cover, ≤4096 entries |
| 0x02 | winner | repeated (device_id(16) ‖ raw op frame) — the verbatim winning frame for every record, tombstones included, ≤200k entries |

Merge semantics: deterministic order `(hlc, device_id, seq)`; per-record
last-writer-wins; tombstone suppresses earlier upserts. All devices
converge to identical state for identical op sets — order-independent.
Checkpoint ops are merge-inert (no record effect).

## Compaction

A checkpoint op asserts: "at covered vector V = {(dev, seq, head)}, the
merge of all covered ops yields exactly this winner set." It is authored
by any device that has fully replayed V, sealed and signed like any op,
and travels through the normal sync path (the relay needs no compaction
awareness — it retains full logs regardless).

Adoption is **verify-or-nothing** — a replica never trusts a checkpoint
on signature alone:

1. Every covered `(dev, seq, head)` must be a head the replica has itself
   verified: its replayed tip, the prev_op_hash of a verified op at
   `seq+1`, or an anchor from a previously adopted checkpoint.
2. Every claimed winner frame must be authentic (device signature +
   DEK open), and `winner.seq <= covered[dev]`.
3. The claimed winner set must equal the winner set the replica computes
   from its own replay of the covered ops.

Only then: the snapshot frame is persisted to `snapshots/`, the covered
vector becomes each log's new hash-chain **anchor**, and covered log
prefixes are dropped (frames with `seq > covered` kept; tmp-write +
rename + dir fsync). `base.vec` records the adopted vector — advisory
only; it carries ids/seqs/hashes, no secrets, and cannot forge ops.

Post-compaction verification anchors at the covered head instead of the
zero hash: a log starting at `seq = covered+1` verifies iff its first
op's `prev_op_hash` equals the covered head. A log still holding its
genesis prefix simply replays from genesis — anchors seed state, replay
is idempotent.

The own-device anchor is applied only when the local log's first frame
is exactly `covered+1` — a crash between adoption and prefix-drop leaves
a full log that still verifies from genesis, never a corrupt state.

Sync cursors are logical `seq` numbers, never log lengths: a fully
covered (empty) local log still pulls from `base.vec`'s covered seq and
pushes `seq > remote_head` frames only. Checkpoint frames themselves
replicate like any op and are dropped once a deeper checkpoint covers
them.

## Head checkpoint

```
ckpt = sig(64) || device_id(16) || seq(8) || head_hash(32)
sig  = ed25519 sign(device_sk, "mypassman/v1/ckpt" || vault_id || device_id || seq || head_hash)
```

Stored outside the vault dir. On unlock, a log that fails to extend the
checkpointed prefix is rejected as rollback/divergence.

## Invariants the format enforces

- Manifest can't be forged or rolled back (owner sig + epoch monotonicity,
  enforced by server CAS too).
- Op can't be forged or transplanted (device sig binds seq+nonce+ct;
  replay = identical bytes = idempotent).
- Log can't be silently truncated (per-device checkpoint + hash chain;
  post-compaction, the chain anchors at the adopted covered head).
- A checkpoint can't be forged: adoption requires the claimed covered
  heads AND winner set to match the replica's own verified replay —
  verify-or-nothing, never signature-only trust.
- A revoked device can't push (server checks registry) nor be
  re-enrolled by anyone but the owner (signature required).
