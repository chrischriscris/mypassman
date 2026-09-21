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

**Revocation is forward-secure.** `pair revoke` removes the device from
the owner-signed registry and burns its tokens; it can't push or pull
again. (Like every password manager: it retains whatever ciphertext it
already saw — rotate exposed secrets.)

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
| revoked device | keep old ciphertext | pull/push anything new |

## Auditing notes

The codebase keeps crypto behind `mpm-crypto` (Argon2id,
XChaCha20-Poly1305, ed25519 — all via audited RustCrypto/dalek crates;
no hand-rolled primitives). Format parsers are bounds-checked TLV
readers. The server never decrypts — its attack surface is parser +
authz logic only, duplicated in TS (`syncd/`) and Rust
(`crates/syncd`) against one spec.
