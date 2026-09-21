# mypassman

A local-first, end-to-end-encrypted password manager whose sync server is
cryptographically blind. Your vault is a folder of signed, encrypted
operation logs; the relay stores and forwards them but cannot read,
forge, or reorder them without detection.

```
┌─────────┐   signed ops    ┌─────────┐   signed ops    ┌─────────┐
│ laptop  │ ──────────────▶ │  relay  │ ◀────────────── │ phone   │
│ (keys)  │                 │ (blind) │                 │ (keys)  │
└─────────┘                 └─────────┘                 └─────────┘
```

## Status

Working software, pre-1.0, unaudited. The author uses it daily via the
CLI and Raycast extension on macOS. Do not yet put your family's
passwords in it.

## What works today

- Encrypted vaults (XChaCha20-Poly1305, Argon2id), signed append-only op
  logs per device, owner-signed manifest
- macOS CLI: items, TOTP, password gen, import/export, backups
- Unlock daemon + Touch ID + Raycast extension (copy/fill/TOTP-paste)
- Multi-device sync through a blind relay — two backends, one protocol:
  - **Cloudflare Worker + Durable Object** (`syncd/`, free-tier viable)
  - **Single Rust binary** (`mpm-syncd`, Docker/VPS/bare metal)
- Device pairing: invite → approve on an enrolled device → done
- Device revocation: `pair revoke` re-signs the manifest + burns tokens

## Quick start

```sh
cargo build --release -p mypassman
./target/release/mypassman init          # creates ~/.mypassman/vault
mypassman add login github -f username=me -f password=…
mypassman list
```

Self-host a relay:

```sh
docker build -t mpm-syncd .
docker run -d -p 8787:8787 -e MPM_SETUP_KEY=<secret> -v mpm-syncd:/data mpm-syncd
# or: wrangler deploy in syncd/  (Cloudflare Workers, free tier)
```

Then on each device:

```sh
mypassman sync init http://your-relay:8787 --setup-key <secret>   # first device
mypassman pair invite                                            # prints <vault>.<code>
mypassman pair join http://your-relay:8787 <vault>.<code>        # new device
mypassman pair approve <prefix>                                  # back on first device
mypassman pair finish                                            # new device
```

See [docs/SELFHOST.md](docs/SELFHOST.md) for production deployment
(TLS, reverse proxy, Cloudflare, docker-compose).

## Design

- **Local-first** — every device holds a full replica; sync is
  opportunistic, never required to unlock or read.
- **Zero-knowledge relay** — ops are end-to-end encrypted and signed;
  the server verifies signatures and sequence integrity but holds no
  keys. Compromise of the relay yields ciphertext + metadata only.
- **Device authority** — each device has an ed25519 key enrolled in the
  owner-signed manifest. Approval is a signature, not a server flag.
- **Merge** — per-record last-writer-wins by (hlc, device, seq);
  tombstones; order-independent convergence.

Specs: [docs/FORMAT.md](docs/FORMAT.md) · [docs/SYNC.md](docs/SYNC.md) ·
[docs/THREATMODEL.md](docs/THREATMODEL.md) · [DESIGN.md](DESIGN.md) ·
interactive explainer: `docs/sync-explainer.html` (open in a browser)

## Layout

```
crates/crypto   primitives: AEAD, Argon2id, ed25519, key bundles
crates/core     vault format, manifest, ops, merge
crates/store    filesystem: logs, checkpoints, device keys
crates/cli      the `mypassman` binary (+ daemon, sync client, pairing)
crates/syncd    `mpm-syncd` — self-host relay binary (axum + SQLite)
syncd/          Cloudflare Worker relay (TS, Durable Objects)
integrations/   Raycast extension
docs/           format + sync specs, threat model, self-hosting
```

## Not done yet

Browser extension, iOS app, passkeys, field-level merge + conflict UI,
snapshot compaction client, multi-user wrap slots, orgs/SSO (deferred —
see THREATMODEL/roadmap discussion), audit.

## License

MIT OR Apache-2.0
