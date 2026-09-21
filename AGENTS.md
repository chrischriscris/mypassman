# Repository Guidelines

## Project Structure & Module Organization

This Rust 2021 workspace implements a local-first, encrypted password manager:

- `crates/crypto`: cryptographic primitives and key bundles.
- `crates/core`: vault format, manifests, operations, and merge logic; `assets/` holds the passphrase wordlist.
- `crates/store`: filesystem persistence; integration tests live in `tests/roundtrip.rs`.
- `crates/cli`: `mypassman`, its unlock daemon, and sync client.
- `crates/syncd`: Rust relay using Axum and SQLite.
- `syncd/`: alternative TypeScript relay using Cloudflare Workers and Durable Objects.
- `integrations/`: Raycast scripts and React extension.
- `docs/`: normative format/protocol specifications, threat model, and hosting instructions.

## Build, Test, and Development Commands

Run Rust commands from the repository root; macOS is the primary CLI development platform and Rust CI environment.

- `cargo build -p mypassman -p mpm-syncd`: build both binaries; add `--release` for optimized builds.
- `MPM_SETUP_KEY=local-dev ./target/debug/mpm-syncd`: start a local relay on port 8787.
- `cargo fmt --all -- --check`: check Rust formatting; use `cargo fmt --all` to apply it.
- `cargo clippy --workspace --all-targets -- -D warnings`: lint with warnings treated as errors.
- `cargo test --workspace`: run all Rust tests.
- In `syncd/`, run `npm ci`, then `npm run dev` for local development or `npm run check` for TypeScript validation.
- In `integrations/raycast-extension/`, run `npm install`, then `npm run dev`, `npm run build`, or `npm run lint`.

## Coding Style & Naming Conventions

Use rustfmt defaults: four-space indentation, `snake_case` functions/modules, `PascalCase` types, and `SCREAMING_SNAKE_CASE` constants. TypeScript uses two-space indentation, double quotes, semicolons, and `camelCase` functions. Preserve strict Worker typing. Keep comments minimal and purposeful; avoid boilerplate docstrings.

## Testing Guidelines

Use Rust's built-in `#[test]` framework, inline test modules, and store integration tests. Name tests after behavior, such as `wrong_password_fails`. Cover tampering, rollback, revocation, and persistence when changing those paths. Run focused cases with `cargo test -p mpm-store --test roundtrip`. No numeric coverage threshold is configured; Worker CI currently checks types.

## Commit & Pull Request Guidelines

History uses concise, imperative subjects, sometimes prefixed by component: `CI:`, `Release:`, or `Fix`. Keep PRs focused; describe behavior changes, link relevant issues, and report validation. Discuss large features in an issue first. Update normative specifications in the same commit as format/protocol changes.

## Security Constraints

Follow `CONTRIBUTING.md`: preserve cryptographic primitives, AAD/domain separation, signature checks, and blind relays. Never give servers decryption keys or searchable plaintext. Report vulnerabilities privately as described in `SECURITY.md`.
