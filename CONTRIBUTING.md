# Contributing

Pre-1.0, maintainer-led. Bug reports and focused PRs welcome; large
features should start as an issue — the crypto/data-model surface is
small on purpose and changes there need a design conversation first.

## Ground rules

- **Crypto is not negotiable in PRs.** No new primitives, no weakening
  AAD/domain separation, no "optional" signature checks. If a change
  touches `crates/crypto`, expect scrutiny.
- **The server stays blind.** syncd (either backend) never gains the
  ability to decrypt — no "convenience" endpoints that hand it keys,
  indexes, or searchable plaintext.
- `cargo fmt`, `cargo clippy --workspace --all-targets -D warnings`,
  `cargo test --workspace` must pass; syncd worker: `npx tsc --noEmit`.
- Specs in `docs/` are normative — if you change the wire format or
  vault format, the doc changes in the same commit.
- Keep comments minimal; match existing style. No AI-generated
  boilerplate docstrings.

## Running the dev loop

```sh
cargo build -p mypassman                 # CLI
cargo build -p mpm-syncd                 # self-host relay
MPM_SETUP_KEY=x ./target/debug/mpm-syncd # local relay on :8787
cd syncd && npx wrangler dev             # Cloudflare backend locally
```
