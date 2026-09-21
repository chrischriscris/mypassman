# mypassman sync protocol v1

The relay is a dumb store-and-forward service for signed ciphertext. It
verifies signatures and enforces sequence integrity, but holds no vault
keys. Two backend implementations exist — Cloudflare Worker + per-vault
Durable Object (`syncd/`) and the single-binary `mpm-syncd` — exposing
the identical API. Either may be replaced; the contract is this document.

## Framing

- Base URL: anything (`https://sync.example.com`, `http://pi.local:8787`)
- All vault routes: `/v/<vault_id>/<route>` — `vault_id` = 32 lowercase
  hex chars (16 bytes). Unknown shape → 404.
- Auth: `Authorization: Bearer <token>` on every route except
  `bootstrap` (setup key) and `/health`.
- JSON for metadata; `application/octet-stream` for op/snapshot bodies.
- Errors: `{"error": "<msg>"}` with a 4xx/5xx status.
- Manifest is transported hex-encoded inside JSON.

## Token scopes

| scope | can do | binding |
|---|---|---|
| `read` | GET manifest/state/ops/snapshot | optional device |
| `write` | read + POST ops (own device only), PUT snapshot | required for ops |
| `admin` | everything + manifest PUT, tokens, invites, revoke | none |

Non-admin tokens with a `device` binding may only act for that device;
a device-bound write token cannot push another device's log — the op
signature check would fail anyway.

Tokens are opaque (`mpm_<random>_<scope letter>`), stored sha256-hashed
server-side, with optional `ttl_s` expiry.

## Routes

### `POST /v/<v>/bootstrap` — create vault

Headers: `x-setup-key: <server setup secret>` (not a vault token).
Body: manifest file bytes (≤ 64 KiB).

One-shot: 409 if the vault exists. The manifest's owner self-signature is
verified before storage. Returns `{"token": "<admin token>"}` — the only
admin token minted without an existing admin.

### `GET /v/<v>/manifest` → `{"manifest": "<hex>", "snapshot_epoch": n}`

### `PUT /v/<v>/manifest` — CAS update (admin)

Body: `{"manifest": "<hex>", "base_hash": "<sha256 hex of stored manifest>"}`.
409 unless `base_hash` matches the stored manifest exactly. Verified:
owner signature, `vault_id` matches bootstrap, `key_epoch` and
`snapshot_epoch` may not regress.

### `GET /v/<v>/state` → `{"snapshot_epoch": n, "heads": [{"device", "head"}]}`

Cheap probe — the client's first call every sync.

### `GET /v/<v>/ops?device=<hex>&since=<seq>&limit=<n>`

`application/octet-stream` response: raw concatenated op frames, seq >
`since`, ascending, ≤ `limit` (clamped 1..256). Headers: `x-head`
(device's global head seq), `x-more` (`1` if truncated). Clients append
frames verbatim to the local log — no decode/re-encode.

### `POST /v/<v>/ops?device=<hex>` — append frames (write token)

Body: concatenated op frames (≤ 1 MiB, ≤ 256/batch). For each frame the
server: decodes header, looks up `device` in the manifest registry
(403 unregistered / revoked), verifies the ed25519 op signature, then in
one transaction enforces `seq == head+1` gap-free append; `seq ≤ head`
must be byte-identical (idempotent replay) else 409 equivocation.
Returns `{"head": <new device head>}`.

### `GET /v/<v>/snapshot[?epoch=n]` / `PUT /v/<v>/snapshot?epoch=n`

Immutable snapshot blobs (write to PUT, read to GET). PUT with an
existing epoch: byte-identical → ok; different → 409. Cap: 8.

### `POST /v/<v>/tokens` — mint scoped token (admin)

`{"scope": "read|write|admin", "device"?: "<hex>", "ttl_s"?: n}` → `{"token"}`.

### `POST /v/<v>/revoke` — burn a device's tokens (admin)

`{"device": "<hex>"}` → `{"removed": n}`. Also drops its pending row.
The cryptographic revocation is the client's manifest update (device
marked inactive, owner re-signed, CAS-pushed); this endpoint is the
server-side companion that kills existing credentials.

## Enrollment

Approval is a signature, not a server flag: a device is enrolled iff it
appears active in the owner-signed manifest. The server's `pending`
table is only a queue.

```
owner device          relay                 new device
    │  invite ─────────▶│                     │
    │  <vault>.<code>   │                     │
    └───────── human carries code ───────────▶│
                      join ── bearer=code ──▶ │ device, vk, name
                      ◀── manifest ───────────│ (proves vault_id, lets
    │  pending ────────▶│                     │  it test the password)
    │  approve: manifest+device, owner-signed │
    │  PUT manifest CAS ─▶│                   │
                      finish ─ bearer=code ─▶ │ device
                      ◀── read+write tokens ──│ invite burned
```

| route | auth | semantics |
|---|---|---|
| `POST enroll/invite` | admin | → `{"code": "XXXX-XXXX", "ttl_s": 900}`. Codes: 8 chars, no confusables, sha256-stored, single-finish. |
| `POST enroll/join` | **invite code as bearer** | `{device, vk, name}` → `{manifest, snapshot_epoch}`. Upserts into `pending`. Code is NOT consumed (finish needs it). |
| `GET enroll/pending` | admin | `[{device, vk, name, created}]` |
| `POST enroll/decline` | admin | `{device}` → drop pending row |
| `POST enroll/finish` | **invite code as bearer** | `{device}` → iff device is active in manifest: `{read, write, manifest, snapshot_epoch}` + invite burned; else 409 "not approved yet" |

Client invite encoding: `<vault_id_hex>.<code>` — the vault id is needed
to route before the device knows anything.

## Sync algorithm (client)

```
state = GET state                       # epochs + remote heads
for each device in manifest.devices ≠ me:
    pull GET ops?device=d&since=<local head> until x-more=0
    append frames verbatim to ops/<d>.log
push POST ops?device=me <frames past remote head>
if remote manifest epoch > local: adopt remote (write verbatim)
if local ahead (device add/revoke):   PUT manifest CAS on remote hash
```

Sync never requires unlock — it transports ciphertext only. The local
daemon merges pulled ops on the next request (verify-only suffix
append), so synced items appear without re-unlocking.

## What the server enforces vs. can't

Enforced: owner sig on manifest, device sig + seq continuity +
hash-chain-adjacent position on ops, CAS on manifest, token scope +
device binding, caps on everything.

Can't: read anything (all content under DEK), forge ops, mint devices,
roll back ops (PK + equivocation check), downgrade the manifest.
Can only: withhold/delay traffic, garbage-collect state (which is why
local retention is authoritative — the relay is never the only copy).
