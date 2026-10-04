# Legacy implementation reference

The previous implementation and uncommitted development progress are preserved
on `archive/pre-rebuild-2026-10-04` at `7435cec`. Main is the fresh implementation.
The archive is a local Git branch; no remote branch has been published by this reset.

Inspect individual files without changing branches:

```sh
git show archive/pre-rebuild-2026-10-04:crates/core/src/lib.rs
git show archive/pre-rebuild-2026-10-04:crates/crypto/src/keys.rs
git show archive/pre-rebuild-2026-10-04:docs/SYNC.md
git ls-tree -r --name-only archive/pre-rebuild-2026-10-04
```

Other atlas references identify their archived paths in `data.js`. The checker
validates that those paths exist on the archive branch. Legacy code and tests
are reuse candidates; their presence does not mean the replacement is implemented
or that the archived code has passed review.

Earlier plans, `DESIGN.md`, `DESIGN.html`, `docs/sync-explainer.html`, and legacy
normative specifications are all on that branch. Reassess them against the
current product brief before adopting their assumptions.

The previous main tip is also available as
`archive/main-before-rebuild-2026-10-04` (`9938e54`).

## Local data

Ignored files, including local Worker state and `.dev.vars`, were captured in
`.local-archive/pre-rebuild-2026-10-04/ignored-files.tar.gz`. Remaining local
legacy directories were moved into the sibling `ignored-worktree/` directory.
The backup is private local data and excluded from Git. An inventory accompanies
the tar archive. Restore local files deliberately into a separate directory;
credentials and vault state do not belong in the clean main tree or its commits.
