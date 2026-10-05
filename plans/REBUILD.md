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
Subsequent local branch cleanup retained main and the two archive branches.
`post-007-remediation` was already contained in the full archive. Unique advisor
and product histories are preserved by tags
`archive/advisor-before-rebuild-2026-10-04` (`bad731c`) and
`archive/product-before-rebuild-2026-10-04` (`be4b695`). Their branch names were
removed. The stale advisor worktree registration was pruned; the product
worktree remains detached at its original commit with its uncommitted files.

## Main's starting boundary

Keep licensing, contribution/security guidance, current requirements, the
architecture proposal, independent review, and the project atlas. Remove the
legacy implementation, build/deployment configuration, old normative formats,
and historical implementation plans from main's active tree.

On 2026-10-05 the maintainer chose to restart main's history. Main no longer
descends from the legacy commits; its first commit is the rebuild starting
point, and the legacy history is reachable only through the archive branches.
The rewritten main was pushed to `origin` the same day. The archive branches
and tags are local; push them separately to keep the legacy history available
remotely.

Reused code must be reviewed and introduced in small, justified increments.
The next step is the revision/key/authority state model, followed by a bounded
two-device experiment. No production format or cryptographic change is approved
merely by making this repository reset.
