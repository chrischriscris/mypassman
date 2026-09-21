# Self-hosting the sync relay

The relay stores only verifiable ciphertext — self-hosting buys you
metadata control and availability independence, not confidentiality
(you already have that cryptographically). Three supported backends, one
wire protocol — clients never know the difference:

| Backend | Infra | Good for |
|---|---|---|
| `mpm-syncd` binary | any VPS / NAS / Raspberry Pi | most self-hosters |
| Docker image | one container + one volume | NAS / compose stacks |
| Cloudflare Worker (`syncd/`) | zero — serverless free tier | "I don't want to run anything" |

All options expose the same `/v/<vault_id>/<route>` API (docs/SYNC.md).

---

## Option A — Docker (recommended for NAS/home lab)

```sh
docker build -t mpm-syncd .
docker run -d --name syncd --restart unless-stopped \
  -p 8787:8787 \
  -e MPM_SETUP_KEY="$(openssl rand -hex 32)" \
  -v mpm-syncd:/data \
  mpm-syncd
```

The image (~100MB) runs unprivileged (uid 10001), stores one SQLite file
per vault in `/data`, and binds `0.0.0.0:8787` inside the container.
Back up `/data` — that's the entire server state.

docker-compose equivalent:

```yaml
services:
  syncd:
    build: .
    restart: unless-stopped
    ports: ["127.0.0.1:8787:8787"]   # behind a reverse proxy
    environment:
      MPM_SETUP_KEY: ${MPM_SETUP_KEY}
    volumes: ["syncd-data:/data"]
volumes:
  syncd-data:
```

## Option B — bare binary on a VPS

```sh
cargo build --release -p mpm-syncd
MPM_SETUP_KEY=<secret> ./target/release/mpm-syncd \
  --data /var/lib/mpm-syncd --bind 127.0.0.1:8787
```

Flags/env: `--data`/`MPM_SYNC_DATA` (default `./syncd-data`),
`--bind`/`MPM_SYNC_BIND` (default `127.0.0.1:8787`), `MPM_SETUP_KEY`
(required for vault bootstrap — without it the relay is read-only-ish:
existing vaults serve normally, new vaults can't bootstrap).

systemd unit sketch:

```ini
[Unit]
Description=mpm-syncd
After=network.target

[Service]
User=mpm
Environment=MPM_SETUP_KEY=__CHANGE_ME__
ExecStart=/usr/local/bin/mpm-syncd --data /var/lib/mpm-syncd --bind 127.0.0.1:8787
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## TLS / reverse proxy

The relay speaks plain HTTP — put it behind TLS. Caddy is one line:

```
sync.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

nginx equivalent: standard `proxy_pass` with `client_max_body_size 2m`.
Clients require a reachable base URL; they'll use whatever scheme you give
`sync init` (`https://sync.example.com`).

## Option C — Cloudflare Workers (zero infra)

```sh
cd syncd
npm install
npx wrangler secret put SETUP_KEY     # the bootstrap credential
npx wrangler deploy                   # → https://<name>.<acct>.workers.dev
```

One Durable Object per vault; free tier covers ~100k req/day and 5GB of
DO SQLite — hundreds of vaults, ~20k syncs/day. See `syncd/README.md`
for the full flow and limits. A **Deploy to Cloudflare** button works if
you fork the repo: point it at `syncd/`.

## First vault bootstrap (all backends)

```sh
mypassman init                                   # local vault
mypassman sync init https://sync.example.com --setup-key <secret>
mypassman sync                                   # pushes manifest + ops
```

`sync init` calls `POST /v/<vault>/bootstrap` with `x-setup-key`, stores
the returned admin token (0600, under the platform data dir — override
with `MPM_DATA`). The setup key is only ever needed for the *first*
device of a *new* vault — rotate it freely; it can't read vaults.

After that, all enrollment is invite-based (`pair invite` / `pair join`
/ `pair approve` / `pair finish`) — no setup key involved.

## Operating notes

- **Backup**: tar the data dir. Each vault is self-contained
  (`<vault_id>.db` on the binary; DO storage on Cloudflare).
- **Upgrade**: restart with the new binary. The SQLite schema is
  `CREATE TABLE IF NOT EXISTS` — forward-compatible.
- **Multiple vaults**: nothing to configure — a vault appears at first
  bootstrap; one deployment serves unlimited vaults.
- **Monitoring**: `GET /health` → `{"ok":true}`.
- **Abuse**: there's no signup and no public bootstrap — `MPM_SETUP_KEY`
  is the only gate on vault creation. Keep it out of the client configs
  of people you merely *host* for (bootstrap their vault for them
  instead, then hand them the invite flow).
