"use strict";

globalThis.MPM_ATLAS = {
  schemaVersion: 1,
  updated: "2026-10-04",
  baseline: "Fresh main · archived implementation 7435cec",
  archive: {ref: "archive/pre-rebuild-2026-10-04", revision: "7435cece995d8b135898f1475f3e91ebb53ef28c"},
  scope: "Main is the fresh implementation starting point. Legacy code is preserved on the archive branch; no replacement implementation or product verification is recorded here.",
  systems: [
    {
      id: "core", name: "Vault engine", tag: "Shared behavior", design: "Proposed", implementation: "not-started",
      purpose: "One place for item operations, validation, permissions, and sync decisions across every client.",
      owns: "The meaning of a vault operation and whether a received change is acceptable. Rust is chosen; the exact public API is open.",
      boundary: "UI, network transport, and platform storage provide inputs and carry out effects. They do not independently reinvent vault rules.",
      flow: ["User intent", "Rust vault rules", "Validated operation", "Platform effects"],
      failure: "An interrupted operation must leave a recoverable, explicit state. Received bytes remain untrusted until validation succeeds.",
      next: "Define revision identity, ancestry, authorization, and the engine's smallest useful interface.",
      done: "Two device instances exercise the same rules; rejection and replay behavior are demonstrated with meaningful tests.",
      decisions: ["language", "rebuild-location", "state-model"],
      sources: [{label: "Current architecture proposal", href: "../ARCHITECTURE-PROPOSAL.md"}, {label: "Archived core (reference)", href: "../LEGACY-REFERENCE.md", archivePath: "crates/core/src/lib.rs"}],
      evidence: [], verification: null
    },
    {
      id: "keys", name: "Keys & devices", tag: "Trust and authority", design: "Open", implementation: "not-started",
      purpose: "Explain who can decrypt, write, administer, enroll a device, or recover access.",
      owns: "People, device identities, protected vault keys, key envelopes, authorization, and rotation.",
      boundary: "Keys used to decrypt stay on clients. Permission to read does not automatically grant permission to sign writes or manage members.",
      flow: ["Person / recovery route", "Authorized device", "Protected vault keys", "Allowed operations"],
      failure: "Revocation cannot erase previously downloaded secrets. Offline clients learn a removal later; old-authority writes need an explicit rule.",
      next: "Specify enrollment, recovery, writer authorization, and removal before freezing key formats.",
      done: "Enrollment, unauthorized writes, key rotation, and recovery are tested against the approved authority model.",
      decisions: ["state-model"],
      sources: [{label: "Key model proposal", href: "../ARCHITECTURE-PROPOSAL.md#what-a-vault-contains-and-who-can-open-it"}, {label: "Archived combined key bundle (reference)", href: "../LEGACY-REFERENCE.md", archivePath: "crates/crypto/src/keys.rs"}],
      evidence: [], verification: null
    },
    {
      id: "storage", name: "Local storage", tag: "Durable state", design: "Proposed", implementation: "not-started",
      purpose: "Make a local save durable and keep accepted records, pending work, and sync progress consistent.",
      owns: "Encrypted records, verified history, pending uploads, and checkpoints. Native SQLite and a transactional browser adapter are proposed.",
      boundary: "A database transaction cannot also commit a network request or attachment file. Cross-boundary operations need persisted stages.",
      flow: ["Validated change", "One local transaction", "Encrypted state + pending work", "Saved on this device"],
      failure: "After interruption, committed work survives and incomplete work can resume. Plaintext fields must not enter database journals or indexes.",
      next: "Derive the schema and atomic operations from the agreed state model, including replay semantics.",
      done: "Interruption and reopening tests show no lost acknowledged saves or skipped incoming work.",
      decisions: ["state-model"],
      sources: [{label: "Persistence proposal", href: "../ARCHITECTURE-PROPOSAL.md#everyday-behavior-including-interruptions"}, {label: "Archived file store (reference)", href: "../LEGACY-REFERENCE.md", archivePath: "crates/store/src/lib.rs"}, {label: "Archived behavioral tests (not run here)", href: "../LEGACY-REFERENCE.md", archivePath: "crates/store/tests/roundtrip.rs"}],
      evidence: [], verification: null
    },
    {
      id: "sync", name: "Sync & conflicts", tag: "Convergence", design: "Open", implementation: "not-started",
      purpose: "Exchange authenticated encrypted changes while preserving concurrent edits and detecting known rollback.",
      owns: "Revision ancestry, conflict representation, replay, verified checkpoints, and the difference between locally saved and remotely acknowledged.",
      boundary: "The relay transports content. Its ordering alone does not prove authenticity or freshness.",
      flow: ["Local committed revision", "Blind relay", "Client validation", "Atomic local acceptance"],
      failure: "Retries must be idempotent. Divergent branches are retained. A fresh device needs a trusted checkpoint; unseen withheld updates are not always detectable.",
      next: "Write a short revision/history model, including concurrent delete/edit and branches with several offline edits.",
      done: "Two-device tests cover divergence, repeated batches, interrupted sync, tampering, and rollback below a trusted checkpoint.",
      decisions: ["state-model"],
      sources: [{label: "Sync behavior proposal", href: "../ARCHITECTURE-PROPOSAL.md#edit-the-same-item-on-two-offline-devices"}, {label: "Archived protocol (reference, not the rebuild contract)", href: "../LEGACY-REFERENCE.md", archivePath: "docs/SYNC.md"}],
      evidence: [], verification: null
    },
    {
      id: "hosting", name: "Hosting service", tag: "Blind storage", design: "Proposed", implementation: "not-started",
      purpose: "Keep a small deployment easy to install, update, back up, and restore.",
      owns: "Service authentication, submission checks, access metadata, encrypted content delivery, and hosting limits.",
      boundary: "The service holds ciphertext and access metadata. It never receives vault decryption keys or searchable plaintext.",
      flow: ["Authorized request", "Relay rule checks", "Durable encrypted storage", "Acknowledgment"],
      failure: "An unavailable service must not prevent access to locally available items. Acknowledgments need an explicit durability meaning.",
      next: "Prove one real operation and an attachment upload on the proposed first host. Measure limits before promising free hosting.",
      done: "A documented deploy/update/restore path works, and measured workloads fit the declared limits.",
      decisions: ["first-host"],
      sources: [{label: "Hosting proposal", href: "../ARCHITECTURE-PROPOSAL.md#web-and-hosting-integration"}, {label: "Archived native relay (reference)", href: "../LEGACY-REFERENCE.md", archivePath: "crates/syncd/src/vault.rs"}, {label: "Archived Worker relay (reference)", href: "../LEGACY-REFERENCE.md", archivePath: "syncd/src/vault.ts"}],
      evidence: [], verification: null
    },
    {
      id: "clients", name: "Clients & autofill", tag: "Platform experience", design: "Proposed", implementation: "not-started",
      purpose: "Make every client fast, accessible, beautiful, and familiar on its platform.",
      owns: "Presentation, autofill, clipboard, OS-protected keys, accessibility, and lifecycle integration.",
      boundary: "Selected plaintext crosses into the UI when needed. Keep transfers narrow and define what locking clears in every process and language.",
      flow: ["Platform interaction", "Narrow core interface", "Selected result", "Native presentation"],
      failure: "Background suspension, lock events, and interrupted autofill must have defined behavior. Hosted web code has a separate delivery trust boundary.",
      next: "Choose the first daily-use client and test unlock/autofill on representative hardware. Keep remaining toolkits open.",
      done: "Representative flows pass keyboard, screen-reader, text-input, lifecycle, and measured resource checks on named devices.",
      decisions: ["first-client", "desktop-ui", "web-ui", "terminal-ui"],
      sources: [{label: "Platform recommendations", href: "../ARCHITECTURE-PROPOSAL.md#platform-technology-recommendations"}, {label: "Client requirements", href: "../PRODUCT-BRIEF.md"}],
      evidence: [], verification: null
    },
    {
      id: "attachments", name: "Attachments", tag: "Bounded file handling", design: "Proposed", implementation: "not-started",
      purpose: "Store and transfer encrypted files without loading an entire large attachment into memory.",
      owns: "Authenticated chunks, complete-file metadata, staging, transfer progress, offline availability, and backup inventory.",
      boundary: "File content is separate from ordinary item records. A ready reference must not silently point to missing content.",
      flow: ["Encrypt bounded chunks", "Durably stage content", "Commit local reference", "Upload before remote ready"],
      failure: "Interrupted uploads resume. Incomplete backups report missing attachments. Chunk ordering and total length require authentication.",
      next: "Specify the chunk format and choose initial size limits and storage on the first host.",
      done: "Interrupted transfers, tampering, missing chunks, and complete backup restoration are covered with bounded-memory measurements.",
      decisions: ["first-host"],
      sources: [{label: "Attachment proposal", href: "../ARCHITECTURE-PROPOSAL.md#attach-a-document-and-restore-it-later"}],
      evidence: [], verification: null
    },
    {
      id: "recovery", name: "Backup & recovery", tag: "Keep access recoverable", design: "Open", implementation: "not-started",
      purpose: "Explain exactly what remains recoverable after losing a device, a password, or the service.",
      owns: "Consistent encrypted backups, required key envelopes, recovery routes, restoration, and fresh device identity.",
      boundary: "A recovery secret is not a backup. Service account recovery alone cannot recreate missing data or decrypt a personal vault.",
      flow: ["Complete encrypted backup", "Valid recovery route", "Fresh device identity", "Safe reconnection"],
      failure: "Restore must work without the old device or relay. Reusing an old device's write sequence can create conflicts or rejected writes.",
      next: "Specify the recovery authority and backup contents; establish whether existing vault migration is needed immediately.",
      done: "Restore verified items and attachments on replacement hardware with the original device and relay unavailable.",
      decisions: ["state-model", "migration"],
      sources: [{label: "Recovery proposal", href: "../ARCHITECTURE-PROPOSAL.md#lose-a-device-or-forget-the-password"}, {label: "Archived recovery code (reference)", href: "../LEGACY-REFERENCE.md", archivePath: "crates/core/src/recovery.rs"}],
      evidence: [], verification: null
    },
    {
      id: "compatibility", name: "Format compatibility", tag: "Safe staggered updates", design: "Proposed", implementation: "not-started",
      purpose: "Prevent an older client from silently losing content created by a newer client.",
      owns: "Versioned envelopes, supported operations, unknown-field preservation, and refusal of unsupported writes.",
      boundary: "Preserving an unknown display field does not justify ignoring unknown security or permission semantics.",
      flow: ["Read versioned record", "Check supported semantics", "Preserve unknown content", "Safe edit or read-only"],
      failure: "An otherwise valid signed revision can still discard fields. Unsupported semantics must stop a write instead of producing silent loss.",
      next: "Define round-trip and minimum-writer rules before the first replacement durable format.",
      done: "Old/new client tests prove lossless supported edits and safe refusal of unsupported operations.",
      decisions: ["state-model"],
      sources: [{label: "Compatibility proposal", href: "../ARCHITECTURE-PROPOSAL.md#compatibility-across-client-versions"}, {label: "Independent review", href: "../reviews/2026-10-04-opus-5-5.md"}],
      evidence: [], verification: null
    },
    {
      id: "sharing", name: "Sharing & SSO", tag: "Future product scope", design: "Proposed", implementation: "not-started",
      purpose: "Support shared vaults, organizations, and identity-provider sign-in while keeping personal use simple.",
      owns: "Membership, reader/writer/admin roles, organization policies, and the distinction between service sign-in and vault unlock.",
      boundary: "An identity-provider login does not inherently provide decryption keys. Administrative decryption authority requires an explicit policy.",
      flow: ["Verify service identity", "Check membership", "Separate vault unlock", "Apply permitted operation"],
      failure: "Removed members retain secrets they already obtained. Offline writes, key rotation, and organizational recovery need explicit authority rules.",
      next: "Make the foundational key model compatible with distinct roles now; implement organization UI and SSO in later phases.",
      done: "Role and removal tests demonstrate the intended authority boundaries; SSO failure and recovery do not silently grant decryption access.",
      decisions: ["state-model"],
      sources: [{label: "Sharing and SSO proposal", href: "../ARCHITECTURE-PROPOSAL.md#share-a-vault-remove-a-member-or-use-sso"}, {label: "Optional collaboration requirements", href: "../PRODUCT-BRIEF.md"}],
      evidence: [], verification: null
    }
  ],
  decisions: [
    {id: "rebuild-location", title: "Fresh implementation on main", status: "Chosen", timing: "Recorded 04 Oct 2026", choice: "Archive legacy progress; rebuild on main", why: "Explicitly chosen by the maintainer. The full code snapshot is preserved at 7435cec, the old main tip has a backup branch, and ignored local data has a private backup.", options: [], source: "../REBUILD.md"},
    {id: "language", title: "Shared core language", status: "Chosen", timing: "Recorded 04 Oct 2026", choice: "Rust", why: "Explicitly chosen by the maintainer. Keep UI dependencies outside the core and measure ordinary edit/test cycles separately from release builds.", options: [], source: "../PRODUCT-BRIEF.md"},
    {id: "state-model", title: "Revision and authority model", status: "Open", timing: "Before durable format", why: "Storage, replay, conflicts, enrollment, revocation, and recovery depend on this. A concrete proposal is still needed before choosing its protocol.", options: ["Draft the state model next", "Review an existing model first"], source: "../ARCHITECTURE-PROPOSAL.md#choices-still-requiring-resolution"},
    {id: "first-host", title: "First hosting path", status: "Proposed", timing: "Before first end-to-end increment", choice: "Cloudflare first; one production host initially", why: "Easy self-hosting is a core goal. Validate a real operation, attachment upload, and restore. A portable native host remains a target.", options: ["Cloudflare first", "Native relay first", "Decide after the feasibility experiment"], source: "../ARCHITECTURE-PROPOSAL.md#web-and-hosting-integration"},
    {id: "first-client", title: "First daily-use client", status: "Open", timing: "Before platform implementation", why: "macOS is the current development environment. Daily use and mobile/browser experiments should guide the first usable client pair.", options: ["macOS first", "Browser extension first", "Mobile first"], source: "../ARCHITECTURE-PROPOSAL.md#first-implementation-boundary-and-how-to-evaluate-it"},
    {id: "migration", title: "Existing vaults", status: "Open", timing: "Before replacing real data", why: "Preserve current code and data. Determine whether immediate migration is required; the proposed migration imports into a new copy.", options: ["Need migration before daily use", "Use disposable test vaults initially"], source: "../ARCHITECTURE-PROPOSAL.md#choices-still-requiring-resolution"},
    {id: "desktop-ui", title: "Windows / Linux UI", status: "Open", timing: "When desktop work starts", why: "GPUI and Slint are candidates. Native behavior, accessibility, input methods, idle resources, and rebuild times need evidence.", options: ["Evaluate GPUI first", "Evaluate Slint first", "Keep both open"], source: "../ARCHITECTURE-PROPOSAL.md#platform-technology-recommendations"},
    {id: "web-ui", title: "Web and extension framework", status: "Open", timing: "When browser UI work starts", why: "Svelte was suggested, and the maintainer raised reservations. Maintainability and measured cost should decide this; no framework is selected.", options: ["Explore Svelte", "Explore React", "Keep the framework open"], source: "../ARCHITECTURE-PROPOSAL.md#web-and-hosting-integration"},
    {id: "terminal-ui", title: "Interactive terminal client", status: "Proposed", timing: "After core behavior is proven", choice: "Clap commands with an optional Ratatui interface", why: "Clap parses commands and flags; Ratatui can provide interactive screens. Both would call the same core.", options: ["Commands first; TUI later", "Include a Ratatui TUI early", "Keep delivery order open"], source: "../ARCHITECTURE-PROPOSAL.md#platform-technology-recommendations"}
  ],
  scenarios: [
    {id: "offline", title: "Save offline, then sync", steps: [
      {title: "Start with a shared revision", a: "Revision 1 · saved locally", relay: "Encrypted revision 1", b: "Revision 1 · saved locally", note: "Both devices have already verified the same starting state."},
      {title: "Device A goes offline and edits", a: "Revision 2 · saved locally · pending sync", relay: "Encrypted revision 1", b: "Revision 1 · saved locally", note: "The encrypted revision and pending work commit together. The client can say saved on this device."},
      {title: "Reconnect and receive acknowledgment", a: "Revision 2 · synced", relay: "Encrypted revision 2 stored", b: "Revision 1 · waiting to receive", note: "Synced means the service acknowledged the upload. It does not mean every device has received it."},
      {title: "Device B validates and commits", a: "Revision 2 · saved locally", relay: "Encrypted revisions retained", b: "Revision 2 · verified and saved", note: "Incoming content and sync progress commit together after client validation."}
    ]},
    {id: "conflict", title: "Two offline edits", steps: [
      {title: "Both devices start at revision 1", a: "Revision 1", relay: "Encrypted revision 1", b: "Revision 1", note: "A shared starting point lets clients relate later revisions."},
      {title: "Each device edits independently", a: "Branch A · saved offline", relay: "Encrypted revision 1", b: "Branch B · saved offline", note: "Neither device has seen the other's change. Each branch can contain more than one edit."},
      {title: "Reconnect and exchange branches", a: "A + B · conflict retained", relay: "Both encrypted branches", b: "A + B · conflict retained", note: "Clients use ancestry to detect divergence. Server arrival order does not silently erase a branch."},
      {title: "The user resolves the conflict", a: "Resolution · references both branches", relay: "Encrypted resolution revision", b: "Resolution received and verified", note: "The exact resolution representation remains a protocol decision. This demonstrates the intended user outcome."}
    ]},
    {id: "interruption", title: "Interrupted incoming sync", steps: [
      {title: "Device B requests new content", a: "Revision 2 · uploaded", relay: "Encrypted revision 2", b: "Revision 1 · old sync cursor", note: "The cursor is transport progress; it does not itself establish trust."},
      {title: "Interrupt before the transaction commits", a: "Revision 2", relay: "Batch can be requested again", b: "Revision 1 · old cursor retained", note: "Receiving or validating bytes is not the same as durably accepting them."},
      {title: "Restart and replay the batch", a: "Revision 2", relay: "Same encrypted batch", b: "Revision 2 + progress committed together", note: "A completed transaction contains both accepted content and corresponding progress. Repeated delivery must be safe."}
    ]},
    {id: "rollback", title: "Known rollback", steps: [
      {title: "Device A remembers a verified checkpoint", a: "Trusted checkpoint 8", relay: "Stores encrypted history", b: "Trusted checkpoint 8", note: "Checkpoint numbering is illustrative. The actual authenticated history representation is still open."},
      {title: "Relay offers state below that checkpoint", a: "Trusted checkpoint 8 retained", relay: "Offers older state 5", b: "Trusted checkpoint 8 retained", note: "A valid old signature alone cannot establish freshness."},
      {title: "Reject the known rollback", a: "Reject response · keep local state", relay: "Cannot force acceptance", b: "Existing local vault still usable", note: "This protection needs remembered trusted state. A fresh device needs a trust anchor; unseen withheld updates may remain undetectable."}
    ]}
  ],
  activity: [
    {date: "2026-10-04", title: "Main prepared for the fresh implementation", kind: "Maintainer decision", detail: "Legacy implementation and work in progress archived at 7435cec. Main retains current requirements, design, review, and atlas. Ignored local data preserved privately.", href: "../REBUILD.md"},
    {date: "2026-10-04", title: "Project atlas introduced", kind: "Documentation", detail: "System chapters, decision drafts, conceptual walkthroughs, and evidence rules. No product implementation is claimed."},
    {date: "2026-10-04", title: "Independent Opus 5.5 review", kind: "Design review", detail: "Reviewed the product brief and architecture proposal. Added compatibility requirements and clarified implementation order. No source audit or product tests.", href: "../reviews/2026-10-04-opus-5-5.md"},
    {date: "2026-10-04", title: "Rust core selected", kind: "Maintainer decision", detail: "Rust chosen with fast development builds and a small, understandable dependency structure.", href: "../PRODUCT-BRIEF.md"},
    {date: "2026-10-03", title: "Product direction recorded", kind: "Requirements", detail: "Local-first, encrypted, lightweight, easy to self-host, all major platforms, and optional organizations/SSO.", href: "../PRODUCT-BRIEF.md"}
  ]
};
