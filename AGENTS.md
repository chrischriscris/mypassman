# Repository Guidelines

## Current phase and structure

Main is a fresh implementation starting point. The legacy code and work in
progress live on `archive/pre-rebuild-2026-10-04` (`7435cec`). The old main tip
is preserved on `archive/main-before-rebuild-2026-10-04`. See
`plans/REBUILD.md` and `plans/LEGACY-REFERENCE.md` before referring to old code.

- `plans/PRODUCT-BRIEF.md`: product requirements and explicit choices.
- `plans/ARCHITECTURE-PROPOSAL.md`: the current design proposal.
- `plans/atlas/`: visual system index, decisions, walkthroughs, and evidence.
- `plans/reviews/`: advisory review artifacts.

Rust is chosen for the shared core. Client and host recommendations remain
proposals unless explicitly recorded as chosen. No replacement Cargo workspace,
implementation, or normative protocol exists yet. Do not use legacy module paths
or commands as though they describe current main.

## Development discipline

Keep changes small, purposeful, and understandable. Define one concrete outcome,
clear component ownership, interruption behavior, and a meaningful completion
check. Avoid speculative abstractions, duplicated rules, unused dependencies,
boilerplate comments, and broad incidental refactors.

Maintain one current architecture and one active implementation plan. Update the
relevant atlas chapter, affected decisions, evidence, and activity in the same
change. Recommendations and browser drafts do not constitute maintainer decisions.
Distinguish proposed, in progress, implemented, and verified. Verification needs
a procedure, result, date, exact revision/snapshot, and limits.

## Verification and style

Current checks, from the repository root:

- `node plans/atlas/check.mjs`
- `node --check plans/atlas/app.js`
- `node --check plans/atlas/data.js`

When Rust implementation starts, establish its build, rustfmt, Clippy, and test
commands here. Use standard Rust naming and rustfmt. Match the atlas's simple
JavaScript, HTML, and CSS style; it has no package installation or build step.
Commit subjects should be concise and imperative. Keep PRs focused and report
behavior, validation, and remaining limitations.

## Security boundaries

Preserve client-side encryption, authenticated validation, domain separation,
and blind hosting. Never give a server decryption keys or searchable plaintext.
Use established cryptographic libraries; consequential key, format, protocol,
and trust changes need an explicit design and meaningful security/recovery tests.
Review any reused legacy implementation before adopting it. Update normative
specifications alongside format/protocol changes once those specifications exist.
Keep local vault data and credentials out of commits. Report vulnerabilities
privately as described in `SECURITY.md`.
