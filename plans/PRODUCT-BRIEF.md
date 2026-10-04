# mypassman product brief

Recorded 2026-10-03 against `b66f308` and the existing uncommitted working
tree. This captures the maintainer's product direction. Architecture and
delivery suggestions remain proposals except for explicitly recorded decisions.

The [architecture proposal](ARCHITECTURE-PROPOSAL.md), added 2026-10-04,
works through the scenarios below and recommends initial system boundaries.

## Product

A lightweight, local-first, cross-platform secure vault that is easy to
self-host. It stores credentials, sensitive records, and encrypted
attachments. Personal use is the primary experience; sharing, organizations,
and organizational SSO belong in the eventual product.

Completeness is a long-term goal. Each release needs a bounded, usable scope.
The maintainer must be able to understand the design and the reasons for each
substantial change.

## Requirements established in the conversation

- **Core language (chosen 2026-10-04):** Rust, with fast development builds
  treated as a requirement. Measure clean builds and ordinary edit/test cycles
  separately, keep the core independent of platform UI dependencies, and
  reserve costly release optimizations for demonstrated benefits. Favor
  straightforward code over elaborate generic or macro-based frameworks.
- **Maintainer control and code quality (confirmed 2026-10-04):** development
  must remain understandable and reviewable as the product grows. Use focused
  changes, explicit module responsibilities and state ownership, purposeful
  code and comments, and tests of meaningful behavior. Explain architectural
  decisions and their tradeoffs before building on them. Avoid speculative
  frameworks, duplicated rules, broad incidental refactors, and accumulating
  overlapping plans. See the architecture proposal's development discipline.
- **Simplicity (explicitly confirmed 2026-10-04):** keep the whole system
  easy to understand, implement, maintain, operate, and use. Prefer the
  simplest design that meets the security and recovery requirements. Extra
  services, dependencies, abstractions, configuration, and special cases need
  a concrete justification. If scope makes that impractical, stage the feature
  while preserving its security requirements and the long-term product goals.
- **Efficiency:** minimize memory, CPU, and background work. Measure locked,
  unlocked-idle, active-use, and unlock costs separately. Preserve password
  protection when optimizing unlock costs. Numeric budgets remain open.
- **Client quality (confirmed 2026-10-04):** clients must be beautiful,
  responsive, and as native-looking and native-feeling as possible. Use each
  platform's conventions for layout, typography, controls, navigation, and
  interaction. Preserve accessibility and resource efficiency. A shared product
  identity should allow platform-specific presentation; UI reuse is worthwhile
  only when it preserves the required experience.
- **Easy self-hosting:** deployment, updates, backups, and recovery should be
  straightforward. Small deployments on a free service such as Cloudflare
  are a target to validate with realistic workloads, including attachments.
- **Platform coverage:** iOS, Android, macOS, Windows, Linux, web, and browser
  extensions. Release order remains open.
- **Broad item support:** passwords, API keys and other credentials, credit
  cards and other sensitive records, plus attachments. Support multiple
  vaults. The exact inventory of built-in item types remains open.
- **Optional collaboration:** sharing, organizations, and permissions should
  fit the eventual design while keeping individual use simple.
- **Optional SSO:** signing in through an external identity provider is a
  future capability, particularly for organizations. Whether SSO also
  unlocks a vault without a master password is unresolved.
- **Retained philosophy:** local access works without the relay; secrets are
  encrypted on clients; the relay never receives decryption keys or
  searchable plaintext. Preserve the repository's security constraints.

## Proposed shape to investigate

1. **Shared client core:** item handling, encryption, local persistence, and
   sync behavior with one clearly documented model. Evaluate reuse from the
   existing project against that model and its tests.
2. **Platform integrations:** interfaces, autofill, secure key storage, and
   lifecycle behavior appropriate to each operating system or browser.
   Validate how much logic can actually be shared before choosing toolkits.
3. **Small hosting service:** stores encrypted content and coordinates sync
   and authenticated access. Keep hosting dependencies few; validate the
   deployment and restore experience as part of the product.
4. **Explicit ownership and membership:** distinguish people, devices,
   vaults, and permissions. Work through sharing and removal before freezing
   the key model. Organization UI and SSO can ship later.
5. **Separate attachment content:** encrypt files on clients and support
   bounded-memory processing. Make download, offline availability, storage
   limits, and inclusion in backups explicit.

Structured item templates and custom fields are candidates for broad item
coverage. Storing an SSH key, generating a TOTP code, and providing a passkey
or SSH-agent integration are different capabilities; list and prioritize
them individually instead of assuming that storing a field implements them.

## First design exercise

Explain these scenarios in plain language before selecting an implementation:

- Create a personal vault, add a login and a card, lock, and reopen offline.
- Enroll a second device and make concurrent edits while both are offline.
- Attach a document, access it on another device, and restore it from backup.
- Lose a device or forget the master password: state exactly what can be
  recovered, by whom, and with which remaining credentials.
- Share a vault with another person, then remove their access: state what
  removal changes and what previously acquired information they retain.
- Sign in through an organization's identity provider: show separately how
  identity is verified and how decryption becomes possible.

For each scenario, identify where data and keys live, who can decrypt or
authorize changes, what the server can learn, and what an interrupted action
leaves behind. Record competing choices and their costs in a short design
note; avoid prematurely writing a complete replacement protocol.

## Proposed delivery approach

The maintainer chose a fresh implementation on main with legacy progress
preserved on an archive branch. Preservation is recorded in the
[rebuild decision](REBUILD.md). Existing vault migration still requires an
explicit plan before using a replacement with real data.

After the design exercise, use small experiments to measure mobile unlock
and autofill constraints, browser feasibility, and free-tier hosting costs.
Choose the first clients from those results and the maintainer's daily use.

The first usable increment should exercise create, unlock, edit, sync, and
backup/restore across two devices. Give it a clear completion test, then add
item capabilities and platform integrations incrementally. Existing vault
migration requires an explicit plan if a new implementation changes formats.

## Relationship to earlier plans

Plans 013–019, preserved on the [archive branch](LEGACY-REFERENCE.md),
contain earlier architecture proposals. Reassess their
assumptions against this brief before selecting implementation work. Their
presence does not settle the new architecture or establish that a rewrite
is required. Existing source, specifications, and tests remain evidence to
evaluate; this document makes no claim that their security has been audited.
