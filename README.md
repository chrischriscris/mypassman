# mypassman

A lightweight, local-first encrypted vault, rebuilt with a small, understandable
architecture. Rust is chosen for the shared core. The replacement is currently
in the design phase; implementation has not started.

Open the [project atlas](plans/atlas/index.html) in your browser. It works
offline and tracks systems, decisions, conceptual walkthroughs, and evidence.

## Current records

- [Product brief](plans/PRODUCT-BRIEF.md): requirements and chosen direction.
- [Architecture proposal](plans/ARCHITECTURE-PROPOSAL.md): proposed boundaries
  and decisions still needed before implementation.
- [Rebuild decision](plans/REBUILD.md): why main starts fresh and what was preserved.
- [Independent design review](plans/reviews/2026-10-04-opus-5-5.md).
- [Atlas maintenance](plans/atlas/README.md): update the record alongside each change.

## Archived implementation

The previous implementation, all tracked work in progress, and earlier plans
are preserved on `archive/pre-rebuild-2026-10-04` at `7435cec`.
The previous main tip is preserved on `archive/main-before-rebuild-2026-10-04`.
These are local branches. See [legacy reference](plans/LEGACY-REFERENCE.md)
for access and local-data preservation details.

Main's history was restarted on 2026-10-05: it starts with the current design
records and atlas, and legacy commits are reachable only through the archive
branches. Bring reviewed code into it deliberately as each component is built.

## Next step

Write a concise state model for revisions, authorization, keys, recovery,
and compatibility. Then prove its critical transitions with a small headless
two-device experiment before expanding clients or hosting modes.

## Current verification

```sh
node plans/atlas/check.mjs
node --check plans/atlas/app.js
node --check plans/atlas/data.js
```

These check the documentation artifact. Rust build/test commands will be
established with the first implementation; no Cargo workspace exists on main yet.
