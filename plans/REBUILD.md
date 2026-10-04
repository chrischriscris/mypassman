# Rebuild location decision

Chosen by the maintainer on 2026-10-04: preserve the existing progress on a
branch and use main for the from-scratch implementation.

## Preserved state

- `archive/pre-rebuild-2026-10-04` at
  `7435cece995d8b135898f1475f3e91ebb53ef28c`: legacy implementation, all tracked
  uncommitted changes, earlier plans, and the current atlas/design snapshot.
- `archive/main-before-rebuild-2026-10-04`: previous main at
  `9938e54` before the rebuild.
- Ignored local files are preserved privately under
  `.local-archive/pre-rebuild-2026-10-04/`; they are not committed to either branch.

The archive snapshot was committed with a clean tracked working tree. The
ignored-file tar archive was checked against every captured regular file.
These preservation checks do not establish correctness of the legacy software.
Other existing branches and worktrees remain independent.

## Main's starting boundary

Keep licensing, contribution/security guidance, current requirements, the
architecture proposal, independent review, and the project atlas. Remove the
legacy implementation, build/deployment configuration, old normative formats,
and historical implementation plans from main's active tree.

Keep normal Git history. This is a new implementation in the same repository;
there is no orphan branch or rewritten history. The branch changes are local.

Reused code must be reviewed and introduced in small, justified increments.
The next step is the revision/key/authority state model, followed by a bounded
two-device experiment. No production format or cryptographic change is approved
merely by making this repository reset.
