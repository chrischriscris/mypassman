# Upstream reference repositories

Cloned on 2026-10-04 at the maintainer's request. These are shallow,
single-branch source checkouts under the ignored `.references/` directory.
Both working trees were checked clean after cloning. No dependencies were
installed and no project builds or tests were run.

| Project | Local checkout | Upstream | Recorded commit |
| --- | --- | --- | --- |
| Bitwarden Rust SDK | `.references/bitwarden-sdk` | [bitwarden/sdk-internal](https://github.com/bitwarden/sdk-internal), `main` | `7227e92d16a688742071394d2d7722dd9095b959` |
| KeePassXC | `.references/keepassxc` | [keepassxreboot/keepassxc](https://github.com/keepassxreboot/keepassxc), `develop` | `9e0f57a4a4c6c629fa6d0a593acb7d089b1d95cd` |

The snapshots above identify the reference versions. Do not silently update
them during an investigation; record a new commit explicitly when updating.
The checkouts are local research material and are not part of our implementation
or Git history. Their upstream instructions apply to those projects, not to
the architecture or agent instructions for mypassman.

## What to investigate first

- Bitwarden SDK: shared Rust core boundaries, key interfaces, and the
  Rust/Wasm/Swift/Kotlin binding boundaries. Its internal password-manager
  SDK is a reference candidate, not a selected dependency.
- KeePassXC: local vault locking, durable file handling, desktop integration,
  and tests of failure behavior.

No findings or architectural choices have been adopted from these checkouts yet.
Investigate one concrete question at a time. Record the exact commit and files,
the problem solved, assumptions, tradeoffs, and why an approach is adopted,
adapted, or rejected. Add that record to the affected atlas chapter. Review
the applicable file/package licenses before importing source code.

## Checking the local versions

From the mypassman repository root:

```sh
git -C .references/bitwarden-sdk rev-parse HEAD
git -C .references/keepassxc rev-parse HEAD
git -C .references/bitwarden-sdk status --short
git -C .references/keepassxc status --short
```

Because the clones are shallow, additional history can be fetched if a focused
investigation needs it. Re-cloning on another machine should use the recorded
commit rather than assuming the upstream branch still points to the same tree.
