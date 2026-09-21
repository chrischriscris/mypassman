# syncd — zero-knowledge sync relay

Cloudflare Worker + one Durable Object per vault (SQLite-backed). Stores only
what it can verify: the owner-signed manifest and device-signed op frames.
No plaintext, no passwords, no keys.

## Deploy

```sh
cd syncd
npm install
wrangler secret put SETUP_KEY   # any strong string; bootstrap auth
wrangler deploy                 # prints https://<worker>.<acct>.workers.dev
```

Free tier covers this: DO request + SQLite storage limits are far above a
personal vault's needs. `SETUP_KEY` is the only secret; rotate it with a new
`wrangler secret put` (existing tokens keep working — it's bootstrap-only).

## First device

```sh
mypassman sync init https://<worker>.<acct>.workers.dev --setup-key <SETUP_KEY>
mypassman sync                  # pushes your ops
```

Stores `admin`/`read`/`write` tokens in
`~/Library/Application Support/mypassman/sync/<vault_id>.conf` (0600).

## New device

```sh
# on the enrolled (admin) device:
mypassman pair invite           # prints <vault_id>.<code>, valid 15 min

# on the new device (fresh vault dir):
mypassman pair join https://<worker>... <vault_id>.<code> --name "iphone"

# back on the enrolled device:
mypassman pair pending
mypassman pair approve <device-prefix>

# on the new device:
mypassman pair finish           # tokens minted, ops pulled — done
```

Approval is cryptographic: `pair approve` adds the device to the
owner-signed manifest; `finish` only succeeds once the server sees the new
device in that manifest — the invite is then burned for tokens.

## Day to day

`mypassman sync` — pull foreign op logs, push your own, reconcile the
manifest. Run it whenever; it's idempotent and needs no unlock. A running
daemon picks up pulled ops on its next request — no re-unlock.

## Endpoints

```
POST /v/:vault/bootstrap        X-Setup-Key + manifest body → admin token (once)
GET  /v/:vault/manifest         read    → {manifest: hex, snapshot_epoch}
PUT  /v/:vault/manifest         admin   {manifest: hex, base_hash} — CAS on sha256
GET  /v/:vault/state            read    → {snapshot_epoch, heads[]}
GET  /v/:vault/ops?device&since read    → raw frames (x-head, x-more)
POST /v/:vault/ops?device       write   raw frames — sig+seq verified per op
GET  /v/:vault/snapshot?epoch   read    → bytes | 404
PUT  /v/:vault/snapshot?epoch   admin   immutable
POST /v/:vault/tokens           admin   {scope, device?, ttl_s?} → {token}
POST /v/:vault/revoke           admin   {device} — burns its tokens
POST /v/:vault/enroll/invite    admin   → {code, ttl_s}
POST /v/:vault/enroll/join      invite  {device, vk, name} → manifest
GET  /v/:vault/enroll/pending   admin   → [{device, vk, name, created}]
POST /v/:vault/enroll/decline   admin   {device}
POST /v/:vault/enroll/finish    invite  {device} → {read, write, manifest}
                                 (409 until the device is in the manifest)
```

Write tokens are device-bound: they can only extend their own chain, and the
server verifies every op's ed25519 signature against the manifest registry —
a leaked write token can't forge another device's ops.
