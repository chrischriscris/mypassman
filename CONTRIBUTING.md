# Contributing

The replacement is in its design phase. Start with the product brief,
architecture proposal, and project atlas linked from the README.

Keep contributions focused. Describe the user-visible outcome, affected
components, interruption behavior, and meaningful completion checks before
implementing substantial changes. Record consequential design decisions and
update the atlas alongside the work.

Use established cryptographic libraries. Preserve authentication, domain
separation, and blind hosting. Servers must never receive vault decryption
keys or searchable plaintext. A passing test suite does not establish an audit.

The current documentation checks are listed in `AGENTS.md`. Establish Rust
formatting, lint, and test gates with the first implementation. Normative
format/protocol specifications must change alongside their implementation.
Legacy specifications on the archive branch are reference material.

Keep code and comments purposeful; avoid speculative frameworks and boilerplate.
Report security vulnerabilities privately through the process in `SECURITY.md`.
