# Threat model

## Guarantees

**The relay learns ciphertext and metadata, never plaintext.**
Vault contents, item names*, passwords, TOTP seeds — all under keys the
server never holds. (*item names are visible to vault members via the
op's DEK layer, not to the server — the op body itself is encrypted.)

**The relay cannot forge.** Ops are ed25519-signed by enrolled device
keys; the manifest is signed by the owner key; both are verified by
every client AND by the server before acceptance. A forged op or
manifest rewrite is rejected at the door.

**The relay cannot reorder or truncate silently.** Per-device seq
continuity + the in-op `prev_op_hash` chain + byte-exact equivocation
rejection mean a dropped or reordered op is detected, not absorbed.

**Enrollment requires the owner.** A new device joins only when an
existing device signs it into the manifest — the server's pending queue
can propose, never approve. A leaked invite code alone yields a pending
row, not access.

**Revocation is forward-secure — and non-destructive.** `pair revoke`
records a *revocation horizon* (`revoked_seq` = the device's seq head on
the relay at revoke time) in the owner-signed manifest and burns its
tokens. Ops the device wrote while trusted (`seq <= revoked_seq`) keep
merging on every replica — a lost phone's history survives its own
revocation — while anything it writes after is rejected at ingest, on
push, and at merge. The device keeps whatever ciphertext it already saw
(like every password manager — rotate exposed secrets). Its own local
writes fail once it learns the new manifest; a fully cut-off device only
learns via the 401s.

By default revoke also **rotates the DEK**: a fresh `key_epoch` is minted,
every wrap slot is re-wrapped, and — because the shared master password is
itself compromised knowledge — the password slots move to a NEW master
password. Ops sealed before the rotation remain readable via DEK history
(the revoked device already saw that data; you can't unread it), but
anything sealed at the new epoch is cryptographically unreachable for the
revoked device even if it obtains the ciphertext — the difference between
"revoked = can't sync" and "revoked = can't read new secrets".
`--keep-keys` skips rotation for cases where secrecy doesn't matter
(tidying an old offline device).

**Foreign-log corruption quarantines, it doesn't wedge.** A device log
that fails verification (bad sig, chain break, undecryptable op — e.g. a
compromised-but-enrolled device pushing signed garbage) is skipped from
its first bad op with a warning; the verified prefix still merges. Unlock
and `pair revoke` stay usable so the owner can actually evict it.

**Manifest replays can't roll back.** `snapshot_epoch` is the manifest
revision — bumped on every owner-signed write, monotone, pinned in both
relay backends. Clients adopt a remote manifest only when its epoch is
strictly newer AND `owner_vk`/`key_epoch` are consistent (owner_vk never
rotates). An equal-epoch/different-bytes state means two owners wrote
concurrently — the relay's copy wins, the loser is told to redo its
change.

## What the relay still sees (metadata)

- vault ids, device ids, device names, enrolled/active status, counts
- op counts, sizes, timing, seq heads; sync frequency per device
- manifest size/epochs; invite/pending churn
- client IPs (unless Tor/VPN)

A hostile relay can also **withhold or delay** sync (availability, not
integrity — clients detect gaps via seq/checkpoint) and **refuse
service**. It cannot silently modify vault history.

## Out of scope / assumptions

- **Endpoint compromise.** Malware on an unlocked device sees plaintext
  — same as every PM. Touch ID/daemon shrink the exposure window; they
  don't eliminate it.
- **Master password quality.** Argon2id slows offline brute force of a
  stolen vault dir; a weak password still loses.
- **The device signing key file.** `devices/*` is 0600 but unencrypted —
  a stolen laptop backup leaks the ability to sign as that device
  (mitigated: revoke it). OS keychain residency is a roadmap item.
- **Multi-user/orgs.** Vault = flat trust domain today: every enrolled
  device sees every item. Per-member wrap slots and org control planes
  are designed-but-unbuilt; sharing a vault today means sharing a master
  password. SSO deliberately deferred — the enrollment ceremony is
  signature-based, so an IdP could only ever gate the *invite*, never
  the keys.
- **Denial of service.** The relay is trusted for availability of the
  sync path only — never for the only copy of data.
- **Supply chain.** You trust the binary you run. Signed releases +
  reproducible builds are roadmap.

## Attack surface summary

| attacker | can do | cannot do |
|---|---|---|
| passive observer of relay | ciphertext, metadata | plaintext, signatures |
| active hostile relay | drop/delay/dup traffic; refuse service | forge, rewrite, reorder undetected, enroll devices |
| stolen sync token (read) | read ciphertext + metadata | write ops (sig-verified), read plaintext |
| stolen sync token (write, device-bound) | replay own device ops, push own signed ops | push as another device, mint tokens, touch manifest |
| stolen setup key | create empty vaults on the deployment | touch any existing vault |
| stolen invite code (in TTL) | insert self into pending | finish without owner's manifest signature |
| revoked device | keep old ciphertext | pull/push anything new; after revoke's key rotation, decrypt post-rotation ops too |

## Auditing notes

The codebase keeps crypto behind `mpm-crypto` (Argon2id,
XChaCha20-Poly1305, ed25519 — all via audited RustCrypto/dalek crates;
no hand-rolled primitives). Format parsers are bounds-checked TLV
readers. The server never decrypts — its attack surface is parser +
authz logic only, duplicated in TS (`syncd/`) and Rust
(`crates/syncd`) against one spec.
