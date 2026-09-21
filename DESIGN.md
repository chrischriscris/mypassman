# mypassman — Design Document

A personal password manager: local-first, end-to-end encrypted, multiplatform,
and engineered for near-zero idle resource footprint.

Status: **v4 — M1 core implemented** (workspace + `crypto`/`core`/`store`/`cli`
crates; init/add/get/list/rm/devices working; op chain + both AEAD layers
tested incl. tamper + wrong-password). Two rounds of adversarial external
review incorporated.

---

## 1. Goals & non-goals

### Goals
- **Single-user**, local-first vault. **No account needed to use it** —
  self-host syncd authenticates by device pairing, not users. A managed
  cloud adds a thin billing/tenancy account that never touches keys (§8).
- **macOS + iOS first-class**, architected multiplatform from day one —
  Windows/Linux/Android/browser join behind the same core.
- **Complete item coverage**: passwords, cards, API keys, TOTP/authenticator,
  generic secrets, identities, SSH keys (see §6 Item model).
- **Near-zero footprint**: when locked, *nothing runs* — 0 MB. Unlocked agent
  <5 MB RSS, TUI <15 MB, GUI <40 MB, warm `get` <10 ms.
- **Auditable**: small dependency tree, own minimal vault format, reproducible
  builds, boring standard crypto only.
- **Sync anywhere**: self-hostable `syncd` (single binary or serverless) as
  the primary transport — phone ↔ laptop over the internet, not just LAN.
  Folder sync stays as the zero-infra fallback. A future managed cloud reuses
  the identical trustless protocol — the server never sees plaintext either way.
- **Multiple vaults** (personal / work) — `vault_id` makes this free.

### Non-goals (v1)
- Team/org sharing, multi-user, access delegation. (Single-item secure
  sharing may land post-1.0 via an age-style ephemeral-link scheme.)
- Managed multi-tenant cloud — post-1.0. When it lands it adds a **thin
  account layer** (email or passkey → owns `vault_id`s → billing, quota,
  abuse controls) on top of the *same* protocol. The account is a tenancy
  shell around opaque blobs: it never sees keys, and vault crypto is
  account-independent — a leaked/forgotten account password can't decrypt
  anything, and device re-pairing + recovery code survive account loss.
- Passkey provider (revisit post-1.0; the record schema reserves room).
- Attachments (post-1.0 — needs a size-bucketed blob store).
- Compression (zstd) — *deliberately excluded*, see §7.

---

## 2. Threat model

**Protects against:**
- Vault theft (device, backup, cloud folder) — everything sensitive is AEAD-encrypted.
- Hostile/curious sync storage — it holds only opaque encrypted ops.
- Offline brute force — memory-hard KDF; *aggressive params are the only real
  defense since no server rate-limits*. A lost vault + weak password = lost data.
- Record tampering, truncation, replay, and cross-vault swapping — per-op AEAD
  with strict AAD binding + hash-chained logs + authenticated manifest.
- Secret leakage via swap/core dumps/crash reports — zeroed+locked memory,
  non-dumpable process, no secrets in logs.
- Clipboard sniffing — advisory concealment + ownership-checked auto-clear.

**Does NOT protect against (don't overclaim):**
- A compromised device *while unlocked* (keyloggers, ptrace, same-user memory
  reads). The agent shrinks the exposure window; it never removes it.
- Metadata leakage via sync: op timing, approximate sizes, device fan-out.
- Managed-cloud account compromise — the account layer gates tenancy and
  billing only; an attacker with your cloud account can *disrupt* sync and
  see vault sizes but cannot decrypt, enroll devices, or forge ops.
- A sync adversary *withholding* an entire device's log (starvation). Detected
  via epoch watermarks + device liveness, not prevented — fundamental limit.
- Local lockout cannot stop offline guessing — failed-attempt delays are
  opportunistic-attacker defenses only, and destructive wipe-on-N-failures is
  **off by default** (self-DoS risk).
- Evil-maid on an unlocked session; coercion.

---

## 3. Architecture

```
┌────────────────────────────────────────────────────────────┐
│ Clients — disposable processes, each optional              │
│  CLI (clap) │ TUI (ratatui) │ GUI │ mobile │ browser ext   │
├────────────────────────────────────────────────────────────┤
│ IPC: unix socket / named pipe → mypassmand (peer-cred auth)│
├────────────────────────────────────────────────────────────┤
│ mypassman-core                                             │
│   vault   — op log, record CRUD, merge, conflict preserve  │
│   crypto  — Argon2id, XChaCha20-Poly1305, BLAKE3, keywrap  │
│   store   — manifest, snapshots, durable IO, backups       │
│   sync    — per-device logs, HLC, tombstones, compaction   │
├────────────────────────────────────────────────────────────┤
│ OS: keychain/TEE, clipboard, fs, suspend events, sockets   │
└────────────────────────────────────────────────────────────┘
```

**Principles**
- **Zero resident footprint when locked.** `mypassmand` is socket-activated
  (launchd/systemd) and exits on lock. Locked state = no process, not a
  process holding secrets "safely".
- **Secrets never leave core.** Clients get handles and scoped, transient
  buffers — never the DEK, never managed-heap strings across FFI.
- **Decrypt-on-demand.** Records rest as ciphertext; only the accessed entry
  decrypts, into a locked+zeroed buffer. No persistent plaintext search index.
- **Every device owns exactly one append-only log.** Nobody writes another
  device's file → folder-sync conflicts become structurally impossible
  (the fix for the single-mutable-file flaw).

---

## 4. Technology choices

| Layer | Choice | Rejected | Rationale |
|---|---|---|---|
| Language | **Rust** (workspace, pinned MSRV) | Go (GC + ~10 MB floor), C++ (safety), Zig (immature crypto ecosystem) | no runtime, manual memory, mature audited-ish crates, best cross-compile |
| KDF | **Argon2id** (params in manifest, calibrated to *weakest* supported device) | PBKDF2 (weak vs GPU), scrypt (dated), Balloon (less reviewed) | best practice; transient spike at unlock is a bounded, deliberate cost — **not** part of idle footprint |
| AEAD | **XChaCha20-Poly1305**, random 192-bit nonces | AES-GCM, counter nonces | sync forks legitimately produce same-version ops → counter nonces risk catastrophic reuse; random nonces don't |
| Derivation / integrity | **BLAKE3** keyed/`derive_key` | SHA-256/HMAC | fast, domain separation via context strings; *not* a substitute for AEAD — used for op hash-chains and subkey derivation only |
| IDs | **Random 128-bit** | content/URL-derived hashes, UUIDv7 | derived IDs leak account inventory to anyone holding the vault; random IDs leak nothing |
| Serialization | hand-rolled **TLV** (versioned) | protobuf (dep weight), JSON at rest (size) | tiny, strict, fuzzable; JSON/CSV only at the import/export edge |
| CLI / TUI | **clap** / **ratatui** | — | boring, complete, low overhead |
| GUI | **SwiftUI native** (macOS+iOS share one codebase — primary platforms settled); Slint or native per secondary platform | Tauri/Electron — a WebView pulls secrets into a **JS heap that cannot be zeroized** and a renderer you don't control; memory is the secondary argument | the UI is a list + detail pane + form; native shells cost little and platform autofill APIs force native on iOS anyway |
| FFI | **uniffi — only when a non-Rust client exists** | hand JNI/Swift glue; adding uniffi on day one | Rust clients call core directly; FFI is a real secrecy boundary (§10) |
| Sync transport | **`syncd`** — self-host binary (Rust+SQLite) **or** CF Worker+R2 serverless; folder sync as zero-infra fallback | any trusted server | server compromise yields encrypted garbage (§8) |
| Build/CI | cargo workspaces, `cross`/zigbuild, cargo-deny, cargo-audit, cargo-bloat, criterion, RSS budgets | — | supply chain + footprint enforced in CI, not aspirationally |

### Footprint & performance budget (CI-gated)

| Metric | Target |
|---|---|
| Locked-state resident footprint | **0 MB** (daemon exits / never starts) |
| Daemon idle RSS (unlocked) | <5 MB |
| TUI active RSS | <15 MB |
| GUI RSS | <40 MB (measured before toolkit commit) |
| Argon2 transient peak | per device class: ≤256 MiB desktop / ≤64 MiB mobile, unlock only, freed after |
| Cold `get` incl. unlock | <300 ms |
| Warm `get` via daemon | <10 ms |
| 10k-record load + merge | <100 ms |
| CLI binary (stripped + LTO) | <3 MB |

---

## 5. Cryptographic design

### Key hierarchy

```
master_password ─Argon2id(salt, m, t, p)→ KEK ─┐
recovery_code   ─Argon2id(salt2,m,t,p)─→ rKEK ─┤ each wraps the
biometric slot  (OS keychain, per device) ─────┘ KEY BUNDLE:
                                              DEK(32B) + owner_sign_priv

DEK ─blake3::derive_key→ k_meta (non-auth metadata MAC)
                      └→ k_rec = derive_key("rec:"+record_id)  per record

owner_sign (Ed25519, random at init) — signs MANIFEST + device registry
device_sign (Ed25519, per device, pubkey in registry) — signs own ops + heads
```

- **Wrap slots wrap a bundle, not just the DEK** — the owner signing key rides
  alongside so every authorized unlock path can sign.
- **Why signatures, not MACs:** `k_meta` is held by *every* device — a MAC'd
  registry proves "someone with the DEK wrote this," so a revoked device could
  un-tombstone itself. Owner-signed manifest/registry + device-signed ops make
  revocation real. `k_meta` remains only for non-authoritative metadata.
- **Device revocation = one atomic transition** (`key_epoch` rotation):
  new DEK + new owner key + **forced new master password** + **new recovery
  code** + new device registry + fresh snapshot, staged as immutable objects
  then published atomically (CAS). Reason: a compromised device may hold the
  old password/recovery KEK — re-wrapping a new DEK under unchanged KEKs lets
  it unwrap instantly. Rotation protects *future* ops only; credentials the
  device already saw must be rotated at their services.
- **No fast-hash unlock check.** Verify by trial-decrypting the wrap slot —
  a stored verifier is a brute-force oracle.
- **Per-record subkeys** (`k_rec`) give domain separation; random XChaCha
  nonces mean no counter state to fork.

### Vault = a directory, not a file

```
vault/
  MANIFEST            owner-signed: vault_id, format_version,
                      min_reader_version, argon2 params, wrap slots,
                      key_epoch, snapshot_epoch, device registry,
                      purged_before_epoch, owner_sig
  ops/
    <device_id>.log   append-only, hash-chained, device-signed ops
  snapshots/
    snap-<epoch>.bin  compacted state + certified per-device chain anchors
```

**Op log entry** — everything sensitive lives inside the AEAD; on disk an op
is `seq(8) || nonce(24) || device_sig(64) || ct`:

```
ct  = XChaCha20-Poly1305(k_ops, nonce,
      aad = vault_id | format_v | key_epoch | device_id | seq,
      pt  = TLV { prev_op_hash, hlc, type, record_id(rnd128), kind,
                  schema_v, created, name, fields_ct, gossip[] })

fields_ct = nonce2 || XChaCha20-Poly1305(k_rec, nonce2,
            aad = vault_id | record_id | key_epoch,
            pt2 = TLV { fields{…per-kind…}, tags, custom_fields?, versions[] })

op_hash = BLAKE3(canonical op bytes)
```

**Two layers, deliberately** (implementation correction to the original
single-layer sketch): `record_id` must live inside the outer ciphertext —
but `k_rec` is *derived from* `record_id`, so it can't key the outer layer
(circular). Hence `k_ops` (one vault-wide ops key) seals the record graph
from the server, while the secret `fields` blob gets a second AEAD under
`k_rec`. A DEK-holder sees name/kind/ids — enough to index and merge —
while field plaintext requires the per-record key: decrypt-on-demand stays
real. `name` sits in the outer layer so `list`/search never touch `k_rec`.

- **`record_id`, `hlc`, `type` are inside the ciphertext.** In the header they
  let a malicious server flip upsert→tombstone (AEAD still verifies — header
  fields not in AAD are unauthenticated) or *selectively suppress one
  record's ops* — strictly worse than whole-log withholding. Server-side
  indexing needs only `(device_id, seq)`.
- **`gossip` kills two attack classes cheaply**: an op records what this
  device last saw of every other device. Any device reading it can detect
  (a) **prefix rollback** of another device's log, and (b) **equivocation** —
  the server serving divergent valid chains to different clients — with zero
  prior local state. Hash chains alone catch neither.
- **`device_sig` signs the canonical op** — shared DEK doesn't prove
  authorship (any DEK holder can derive `k_rec` and forge another device's
  ops). Signatures verified against the enrolled registry + revocation cutoff.
- **Canonical encoding is law**: fixed-length fields, fixed order, domain-
  separated hashes; reject duplicate keys and noncanonical encodings.
  `prev_op_hash` must equal the actual predecessor *in this file* — that's
  what makes cross-log op relocation fail.
- **HLC is ordering, not authority.** Ops with `hlc > now + skew` are
  *quarantined* (not dropped — legit clock skew exists); equal HLCs break by
  deterministic hash; conflict UI always shows "version from device X, dated
  Y" so a future-dated win is visible.

**What this buys**
- **Structural conflict-freedom at the fs layer** — only the owning device
  writes its log; sync conflicts at file level are impossible.
- **Truncation/tamper evidence** — hash chains + device signatures; a mid-log
  cut or splice fails verification. Chain break ⇒ loud error, quarantine the
  suffix, explicit user salvage (salvage never silently overrides the chain).
- **Membership + rollback detection** — snapshot manifest signs the full
  record set AND per-device chain anchors `{device_id, seq, head_hash}`;
  gossip vectors catch rollback/equivocation between snapshots.
- **Targeted-suppression resistance** — server sees only opaque per-device
  sequences; it cannot tell which record an op touches.
- **Cross-vault replay resistance** — `vault_id` + `device_id` + `key_epoch`
  in every AAD.

---

## 6. Item model

Every record is a typed **item**: one `kind`, one `schema_v`, per-kind field
schema. Common meta on all kinds: `name`, `tags`, `favorite`, `created`,
`modified_hlc`, `versions[]` (history + preserved conflicts), `custom_fields`.

| kind | key fields | notes |
|---|---|---|
| `login` | username, password, urls[], totp? | the default; TOTP embeds here or standalone |
| `card` | number, exp_month/year, cvv, holder, pin?, brand, billing_addr? | cvv/pin masked by default, separate reveal action |
| `apikey` | key, secret?, endpoint, env, scopes?, expires? | dev credentials; feeds `mypassman run` |
| `totp` | secret, algorithm, digits, period, issuer | standalone authenticator entries; `otpauth://` import (+ QR scan on mobile) |
| `secret` | text/blob + custom fields | .env bundles, software licenses, seed phrases* |
| `identity` | name, address, phone, email | form autofill companion to `card` |
| `sshkey` | private, public, fingerprint, comment | dev power feature; can feed ssh-agent via daemon |
| `attachment` | blob_ref, filename, size, mime | **post-1.0** — separate size-bucketed blob store |

\* seed phrases live fine in `secret`; docs should note the hot-vs-cold
storage debate honestly rather than pretend it away.

**Per-kind hardening notes**
- `card.cvv`/`card.pin`/`sshkey.private`/`totp.secret` get the masked-by-default
  treatment: never rendered in list views, reveal is an explicit action,
  excluded from clipboard bulk ops.
- `schema_v` per kind → field evolution without format migrations.

**Power features this unlocks (the "complete" part)**
- `mypassman run --item github/apikey -- npm publish` — injects item fields
  into a child process env (1Password `op run` equivalent); secrets never hit
  disk, shell history, or `.env` files.
- `mypassman inject .env.tpl` — template rendering for dev environments.
- `mypassman otp <item>` — current TOTP to stdout/clipboard.
- `mypassman ssh-add <item>` — load an `sshkey` into the agent.
- Password health across kinds: reused passwords, expired/expiring API keys
  and cards, weak/generated-vs-human analysis.

---

## 7. Storage & durability

- **Durable writes**: append → `fsync` file → `fsync` dir. Atomic rename for
  manifest/snapshots, same fsync discipline. Rename alone is *not* durability —
  the code path is platform-aware (incl. macOS `F_FULLFSYNC`).
- **Hostile-input bounds**: on open, validate Argon2 params against a device
  cap *before* allocating (a tampered manifest claiming 64 GB is a DoS), and
  bound op/record lengths before reading.
- **Snapshots & GC**: compaction merges all logs into `snap-<epoch>.bin`,
  which certifies per-device chain anchors `{device_id, seq, head_hash}` +
  `key_epoch` — a rejoining device's log restarts chain verification from its
  certified anchor. GC policy: `max(retention_days, all-devices-acked)`;
  pruning a log whose device hasn't acked is a **user-visible decision**
  ("old iPad hasn't synced in 90 days — pruning makes its unsynced edits
  unmergeable"). Never fully automatic: an indefinitely offline device can't
  be distinguished from a dead one.
- **Resurrection guard**: manifest carries `purged_before_epoch`; pre-watermark
  ops for records absent from the snapshot are **rejected**, not applied —
  otherwise an offline device's stale upsert resurrects a tombstoned record.
  Tombstone knowledge outlives the deleted ciphertext.
- **Single writer per device**: app/extension/CLI serialize appends through
  transactional local storage — local concurrency must not fork an honest
  chain. Restoring from backup reconciles first or starts a **new device
  incarnation**; an old writer identity resuming unaware of later writes is a
  self-inflicted equivocation.
- **Backups**: rotating encrypted snapshots + a snapshot before *every*
  migration + a tested restore path. Corruption/user-error will beat attackers
  to your data.
- **Salvage**: replay any log, keep AEAD-valid ops — one corrupt op never
  kills the vault. But a chain break is exactly what a splice looks like:
  salvage is loud, quarantines the suffix, and requires explicit user action.
- **No compression.** Compress-then-encrypt leaks plaintext structure through
  ciphertext length (a random password compresses differently than a
  passphrase). Vaults are kilobytes — skip it. If attachments ever land,
  compress those fields only, post-pad.

---

## 8. Sync & merge

**Unit of replication:** files in `ops/` and `snapshots/` — never merged at
the file level, only at the op level, on read.

**Merge semantics (no silent LWW):**
- Same `record_id`, sequential edits → max-HLC wins.
- Same `record_id`, *concurrent* edits → winner by HLC, **loser preserved**
  in `versions[]` and surfaced in UI ("2 conflicted versions"). Password
  history exists anyway; conflicts ride it. Locking yourself out of a real
  account because the newer password was silently dropped is the failure mode
  this design exists to prevent.
- Optional field-level merge later (disjoint fields merge cleanly); v1 keeps
  record-level winner + preserved loser — explainable, testable.
- **Tombstones** are real ops revealing only `(device_id, seq)` — `record_id`
  lives inside the ciphertext. A tombstone beats an upsert iff its HLC is
  later. Purged at compaction, but the `purged_before_epoch` rejection
  frontier (§7) prevents resurrection by lagging devices.

**Rollback/starvation detection:** owner-signed manifest `snapshot_epoch` is
monotonic; each device persists a high-water mark of (epoch, per-device op
counts); op-level gossip vectors let *fresh* devices detect rollback and
forks without local state. Regression → loud warning, refuse to auto-apply.
The nastiest remaining case — a server serving a valid *old* manifest +
snapshot to a freshly restored device (re-enrolling a revoked device, old
`key_epoch` as current) — is mitigated by owner-signed manifests, monotonic
pinning, and printing the epoch in the recovery kit + UI so a human can
eyeball it. A withheld device log is detectable (device "goes silent") but
not preventable — documented in `docs/THREATMODEL.md`.

**Folder-sync reality:** Syncthing/Dropbox/iCloud transport *files*, including
conflict copies and partial writes. Per-device logs make our own files
conflict-proof; conflict-copies of *manifest/snapshots* are merged by taking
the max valid epoch. iCloud can serve stale partials → reads always verify
MAC + chain before trusting.

### syncd — the "anywhere" transport

API surface: `GET /ops?device=&since=seq` (paged), `PUT` immutable objects,
`GET`/`CAS-PUT` manifest+snapshots, optional `GET /hint` (WS/SSE). **Trust
lives in the format — but the server still enforces.**

**Server-side rules (syncd is dumb, not naive):**
- **Gate reads too.** Public ciphertext = bulk harvest + offline brute-force
  oracle on the password wrap slot + traffic analysis. Scoped capabilities:
  `read` / `write` / `admin` / `enroll` are *separate* grants; a device-write
  token can't replace the manifest, publish snapshots, mint tokens, or GC.
- **Immutable objects**: `PUT` with same ID + same bytes = OK; same ID +
  different bytes = reject. Manifest/snapshot publication is compare-and-swap
  on `snapshot_epoch`. Never trust `?device=` or a path as authorization —
  bind each token to (vault, device_id, scope, lifecycle).
- **Cursor semantics**: per-device sequence positions, bounded pages,
  explicit `snapshot_required` after GC. Clients verify continuity across
  pages; an empty page is not proof of full disclosure.
- **Bound everything before buffering**: object size/count, vault bytes,
  devices, enrollment attempts, hint connections, per-token and per-IP rates.
  A compromised-but-authorized client can still exhaust storage.
- **Tokens**: `Authorization` header only (never URL — access logs), stored
  in OS keychain not dotfiles, renewal fails post-revocation, commit-time
  authz check (in-flight writes of a just-revoked token die). Consider
  signing writes with the device key so a leaked token isn't a write
  capability.
- **Hints are untrusted wakeups**: authenticated + server-debounced; an
  unauthenticated hint channel is an activity-tracking oracle, unthrottled
  it's a battery attack on your other devices.
- **syncd is never the durable copy.** Local retention is independent of
  server state — if GC trusted "the server has it," a rolled-back SQLite
  loses ops permanently.
- **Backend equivalence needs a transaction story**: SQLite commits related
  metadata atomically; R2 needs conditional publication or a coordinator —
  object-level consistency doesn't give cross-object transactions. R2 list is
  eventually consistent → don't build cursors on list.

**Deployment options (same protocol, three backends):**
- **Self-hosted binary**: single Rust binary + SQLite, ~10 MB RSS, runs on a
  VPS / Raspberry Pi / NAS. Front with TLS (Caddy auto-HTTPS) or expose only
  on Tailscale — simplest, zero third parties.
- **Serverless**: a Cloudflare Worker + R2 implements the same endpoints;
  free tier covers personal scale, globally reachable, nothing to administer.
  This *is* the pragmatic "cloud option" — you run it on your own CF account,
  so it stays self-hosted in spirit.
- **Managed cloud (post-1.0)**: same code + a thin account layer —
  email/passkey auth → owns `vault_id`s → billing, quota, abuse controls.
  Same trust model: accounts gate tenancy and payment, never decryption.
  `enroll`-scope credentials stay device-to-device; the account can list
  your vaults' sizes but can't add devices or read ops without a paired
  device's signature chain.

**Device enrollment:** new device generates `device_sign` keypair → pairs via
short code/QR with an enrolled device → enrolled device signs the new device
into the registry (owner-signed manifest update) + writes its wrap slot.
syncd gets a scoped read/write token; `enroll`-scope credentials never live
on ordinary sync paths. Revocation = signed registry tombstone + token delete
+ atomic `key_epoch` rotation (§5).

**Push (optional):** authenticated WS/SSE "new epoch" hint → clients re-pull
and verify. On iOS see §9 — `BGAppRefresh` is unreliable; design foreground
sync + extension-local pull, not hints-as-correctness.

---

## 9. Clients, autofill & daemon

| Phase | Client | Autofill story |
|---|---|---|
| P1 | **CLI + `mypassmand`** on macOS (socket-activated daemon; peer-cred auth on unix socket) | `get | pbcopy`, `run`, `otp`, `ssh-add` |
| P2 | **iOS app** (SwiftUI + uniffi→Swift) — needed early because it's a daily-driver platform, and its AutoFill extension + syncd dependency force hard boundaries while code is small | AutoFill Credential Provider extension, FaceID unlock via Keychain wrap slot |
| P3 | **macOS app** (SwiftUI, shares the iOS UI codebase) + menu-bar item | global hotkey → search → autotype; Safari Web Extension via native messaging |
| P4 | **Browser extensions** (Safari first — it's the macOS default — then Chrome/Firefox family) — thin shell over native messaging | strict origin+frame matching, per-fill consent, extension-ID allowlist on the native host |
| P5 | Windows / Linux / Android: CLI ports first (core is already portable), then native or Slint GUIs; Android Autofill Service | platform autofill APIs; Wayland autotype via uinput/ydotool — flagged risk |
| P6 | TUI (ratatui) — fun, not load-bearing | same IPC |

**Why iOS moved up:** you live on phone+laptop, and iOS is the hardest client
(sandboxing, AutoFill extension, Keychain semantics, no mlock). Building it
early validates uniffi, the wrap-slot model, and syncd while the codebase is
small — porting those decisions later is painful. macOS+iOS sharing one
SwiftUI codebase makes native (not Slint) the right GUI call for the primary
platforms; secondary platforms pick Slint or native per cost/benefit.

### iOS breaks the daemon model — design for it explicitly

- **There is no daemon on iOS.** App, AutoFill extension, and share extension
  are *separate processes* sharing only an App Group container + Keychain
  access group. "Unlocked" on iOS = a keychain item + timestamp — a
  materially different security model that gets its own paragraph in
  `THREATMODEL.md`. Core must work **in-process, no IPC**; if the desktop
  daemon shapes core's API around the socket boundary, iOS re-litigates it.
- **Spike the AutoFill extension before the format freezes.** Memory ceiling,
  cold-launch latency (credential picker must appear fast), and
  snapshot-size-to-first-decrypt all push back on Argon2 params and snapshot
  layout — discover those at M0/M1 with a throwaway extension opening a fake
  vault, not at M4.
- **Biometric wrap must be `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`**
  or iCloud Keychain silently replicates the DEK wrap to every Apple device
  you own — defeating per-device slots entirely.
- **Biometric invalidation is a daily-path lockout:**
  `BiometryCurrentSet` invalidates when the user adds a face/finger → the
  extension's fallback is "open the main app to unlock," and the main app
  hands a short-lived unlock token through the App Group. Test this path
  explicitly; it's the first thing that breaks.
- **Keychain accessibility is a hard choice, not a detail**: background sync
  may move ciphertext, but validation/rewrapping waits for permitted key
  access — never weaken accessibility class to keep sync running.
- **Sync on iOS is foreground-pull.** `BGAppRefresh` won't reliably run and
  WS hints don't exist in background. APNs is the only real push — and it
  leaks sync timing to Apple + needs a token registry on syncd. Design
  decision: foreground + in-extension pull; APNs optional later, documented
  as a privacy tradeoff.
- **Suspension mid-operation**: sync and `key_epoch` rotation must be
  resumable — assume the process dies between any two writes; both are
  staged/immutable-publish designs partly *because* of this.
- **uniffi honesty**: FFI hands Swift `String`/`Data` on a heap you can't
  zeroize → handle-based APIs + `reveal(handle, into:)` from M1. The final
  hop into `UITextField`/AutoFill is an unzeroizable NSString no matter what
  — don't claim otherwise.
- **Pairing direction**: phone-scans-desktop vs desktop-scans-phone changes
  which side holds the ephemeral key → spike with the phone in the loop
  before M3 ships.

Autotype remains the universal fallback — works in browsers, terminals,
Electron, anywhere a keyboard works.

---

## 10. Secrecy & hardening checklist

- `zeroize` on all key material and decrypted secrets (KEK, key bundle,
  derived record keys, field plaintext, `Item` values, generated passwords).
  **`mlock` was evaluated and removed**: it can't be done correctly for
  movable structs — `mlock`ing a page then moving the struct leaves a
  secret copy pinned in the freed page, strictly worse than not locking.
  Correct pinning requires `Pin<Box>` + a stable allocation contract
  across every layer that touches keys; revisit if a secrets-handling
  audit shows it's needed. `RLIMIT_MEMLOCK` is also 64 KiB on stock Linux
  and unavailable on iOS. Pair with `RLIMIT_CORE=0`, non-dumpable
  (`prctl`/`PT_DENY_ATTACH`), Yama scope, and assume encrypted swap.
- **FFI is a secrecy boundary**: managed heaps (Swift/Kotlin/JS) can't be
  zeroized. Cross-boundary APIs return handles or `Zeroizing<Vec<u8>>`
  buffers, never `String`. Prefer flows that keep the secret in-process
  (autotype, native-messaging fill) over copying it out.
- **Clipboard**: advisory concealment only (`org.nspasteboard.ConcealedType`
  is a convention well-behaved apps *choose* to honor; mark non-syncable or
  Universal Clipboard ships it to your other devices). Auto-clear only after
  checking the clipboard still holds our value. Prefer autofill over
  clipboard wherever possible. *Implemented in CLI: macOS writes via
  JXA/NSPasteboard with Concealed+AutoGenerated markers; detached
  `__clipclear` janitor clears after 45 s iff unchanged (payload hash via
  stdin, never argv). Same janitor on Linux (`wl-copy`/`xclip`/`xsel`) and
  Windows (`clip`/powershell) — concealment markers there need native
  bindings (`x-kde-passwordManagerHint`, `ExcludeClipboardContentFrom-
  MonitorProcessing`), deferred to the GUI milestone. iOS/Android get it
  free: `UIPasteboard` `localOnly`+`expirationDate`, `EXTRA_IS_SENSITIVE`.*
- **Auto-lock**: idle T, suspend, screensaver, explicit → zeroize + daemon
  exits.
- **Biometric unlock is platform-specific** — "Secure Enclave wraps the DEK"
  is not literally possible (SE holds P-256 keys only):
  - macOS/iOS: Keychain item with `kSecAccessControlBiometryCurrentSet`
    *or* SE P-256 key doing ECIES-wrap of the DEK — different properties,
    pick deliberately.
  - *Shipped today (unsigned CLI):* LAContext prompt gates a plain-keychain
    KEK that wraps the bundle in `SLOT_BIOMETRIC`. The ACL'd-item and
    Secure-Enclave paths were tried first — both need a signed binary
    (`errSec -34018` on access-controlled items, `Kill: 9` on the
    restricted entitlement). So the current gate is user-presence, not a
    hardware boundary: a same-uid process could read the KEK without the
    prompt. A signed release upgrades to the SE design with zero format
    change — the slot already binds vault_id + key_epoch.
  - Android: Keystore/StrongBox AES key, `setUserAuthenticationRequired`.
  - Windows: Hello/DPAPI. Linux: secret-service, TPM2 optional.
- **Failed-attempt handling**: local escalating delay only; optional
  "destroy biometric wrap after N failures" off by default. No lockout can
  stop offline guessing — KDF params do that job.
- **Audit log is LOCAL-ONLY, never synced.** Logging unlocks/failures/exports
  inside the vault turns reads into write ops (sync amplification) and
  publishes your activity pattern as op counts. Per-device local log, or drop
  it. Password health = explicit user-initiated full-decrypt operation —
  never a background job (it contradicts decrypt-on-demand).
- **What a hostile server still can do** (documented, accepted): freeze one
  device's view (stale manifest) — mitigated by gossip + epoch display;
  observe that a `key_epoch` rotation happened (compromise-response signal);
  withhold entirely. Deletion, delivery, and global recency can't be
  guaranteed cryptographically.
- **Supply chain**: committed `Cargo.lock`, cargo-deny (advisories+licenses),
  minimal deps, reproducible builds, signed releases (cosign/minisign),
  signed update manifest — the update channel is part of the threat model.
- **Fuzzing**: `cargo-fuzz` over manifest/op/TLV/importer parsers — synced
  files are attacker-reachable input. Proptest merge invariants:
  idempotent, commutative, associative.
- **Versioning**: `format_version` + `min_reader_version` in the MAC'd
  manifest; refuse newer, never silently downgrade, snapshot before migrate.
  Format freezes at first release; every later change is a migration with
  test vectors.
- **Independent audit** before claiming "safe for real secrets" — self-review
  is not an audit.

---

## 11. Recovery & lifecycle (v1, not later)

- **Emergency kit**: at `vault init`, generate a 128-bit recovery code
  (26-char Crockford-ish base32, `xxxx-xxxx-…`, typo-tolerant: `o→0`,
  `i/l→1`); it Argon2id-derives an independent KEK that wraps the key
  bundle in `SLOT_RECOVERY`. Printed once, stored offline. Rotate with
  `mypassman recovery rotate` — invalidates the old code. Implemented. Lost master password
  is the *most likely* catastrophic event for a personal vault.
- **Backups**: automatic rotating encrypted snapshots; restore path tested in
  CI, not just written.
- **Import**: CSV / KDBX (KeePassXC) / Bitwarden / 1Password — without import
  you won't dogfood; **export** (plaintext JSON, loud warnings) so the tool is
  never a roach motel.
- **Device revocation**: atomic `key_epoch` transition — new DEK + new owner
  key + new password + new recovery code, staged then CAS-published (§5).
  Honest limit: it evicts *future* access; anything the device already saw
  must be rotated at the service. Recovery kit prints `key_epoch` so a
  human can spot a rollback.

---

## 12. Roadmap

| Milestone | Deliverable |
|---|---|
| M0 | `docs/FORMAT.md` + `docs/THREATMODEL.md` + `docs/SYNC.md` + test vectors + workspace + CI gates + **throwaway iOS AutoFill-extension spike** (measures memory ceiling, cold-launch latency, Argon2 fit — before anything freezes). **Spec before code.** ◐ *partial*: spec docs + CI landed retroactively (post-M3); test vectors + iOS spike still open. |
| M1 | `core`+`crypto`+`store`: vault init/open/CRUD/merge + all item kinds, fuzzed + proptested, handle-based secrecy API, single device, **no sync yet**. Format v1 freezes here — informed by the M0 spike. |
| M2 | CLI + daemon (macOS): ~~init/unlock/add/get/list/edit/copy/reveal, gen, recovery kit, TOTP/`otp` (RFC 6238, SHA-1/256/512, `otpauth://`), `run` env injection, unix-socket daemon w/ idle auto-lock + `lock`, MPMEXP passphrase-sealed export/import + CSV import (Bitwarden/1Password), verified backup/restore, Touch ID unlock (`bio enroll`/`bio off`)~~ ✓. **Daily-usable on your laptop.** |
| M3 | `syncd` self-host binary + device enrollment (pairing direction spiked *with* a phone) + merge + tombstones + compaction + conflict UI + gossip-vector verification. Test matrix: two offline devices editing one record, day-skewed clock, mid-sync partial file, restored-from-backup device, atomic `key_epoch` rotation, equivocation detection. **Phone↔laptop anywhere sync lands here.** ◐ *partial*: two interchangeable relays behind one wire protocol (`docs/SYNC.md`) — CF Worker + per-vault DO (`syncd/`) and single-binary `mpm-syncd` (axum+SQLite, Docker-able); `mypassman sync` push/pull, `mypassman pair` invite/join/approve/decline/finish + `pair revoke`/`devices`, daemon live-merge of pulled ops. Still open: compaction/snapshots, conflict UI, gossip vectors, restored-device handling, full matrix. |
| M4 | iOS app (SwiftUI + uniffi) + AutoFill extension + FaceID unlock (ThisDeviceOnly) + foreground-pull sync + `otpauth://` QR import. **The "use it everywhere" point.** |
| M5 | Minimal macOS app — shares the iOS SwiftUI codebase, so it's nearly free and kills the "CLI-only on your work machine" inversion; menu bar + autotype + TouchID |
| M6 | Safari Web Extension + native messaging host; then Chrome/Firefox |
| M7 | TUI; CF Worker syncd backend; Windows/Linux/Android CLI ports |
| M8 | GUI+autofill on secondary platforms (Slint/native per platform), managed-cloud spike if desired |
| M9 | External audit, reproducible releases, 1.0 |

---

## 13. Alternatives considered

| Option | Verdict |
|---|---|
| Fork KeePassXC | C++/Qt, heavy, legacy format — but KDBX **import** is mandatory |
| pass + age/gpg | Right spirit; per-secret files + gpg UX fails the product bar |
| Bitwarden self-host | Heavy server + JS clients — fails footprint goal outright |
| 1Password | Closed + Electron. UX reference only |
| age/rage | Format inspiration: chunked AEAD, simple header, streaming |

---

## 14. Risks & open questions

- **Argon2 params are baked per-vault** — a desktop-tuned vault can OOM-kill
  the iOS app. Cap ≈256 MiB with higher `t`; calibrate to the weakest device
  class; params profile per wrap slot if needed.
- **Wayland autotype** is fragmented (portals/uinput); may need
  compositor-specific paths.
- **iOS sync** — resolved by syncd at M3/M4; iCloud Drive file sync remains a
  free fallback but stale-partial behavior makes syncd the primary path.
- **Log GC safety** — policy is `max(retention, all-devices-acked)` +
  user-visible prune decisions; `docs/SYNC.md` must nail the cutoff/rebase
  semantics for revoked and long-offline devices.
- **Signature overhead** — device sig + owner sig + gossip vector adds
  ~100 B+/op; acceptable, but snapshot anchors must not bloat.
- **Owner key custody** — signing key rides in every wrap slot; a device that
  only needs read/write shouldn't necessarily hold owner_sign → consider a
  separate "admin" slot tier so daily drivers can't re-enroll devices.
  Open question for FORMAT.md.
- **Scope creep** — sharing/passkeys/orgs stay non-goals until 1.0.

---

## 15. Repo layout

```
mypassman/
  crates/
    core/     op log, records, index, merge, conflict preservation
    crypto/   kdf, aead, keywrap, subkeys, locked memory
    store/    manifest, snapshots, durable io, backups
    sync/     log replication, HLC, tombstones, compaction
    cli/      clap CLI
    daemon/   mypassmand (socket-activated agent)
    tui/      ratatui app
    gui/      SwiftUI app (macOS+iOS shared); Slint/native per secondary platform
    ffi/      uniffi bindings (Swift first, Kotlin later)
    nmhost/   browser native-messaging host
    import/   CSV / KDBX / Bitwarden / 1Password importers
    syncd/    self-host sync server (Rust+SQLite binary; CF Worker backend)
  docs/       FORMAT.md · THREATMODEL.md · SYNC.md
  DESIGN.md   (this file)
```
