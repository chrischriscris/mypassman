# Security policy

mypassman is pre-1.0 and unaudited. Please report vulnerabilities
privately — do NOT open a public issue for a security bug.

## Reporting

Email the maintainer (see git history / GitHub profile for contact), or
use GitHub's private vulnerability reporting on this repository.

Include: affected component (`crates/*`, `syncd/`, integrations),
reproduction, and whether you have a working exploit or a code-reading
finding. We'll acknowledge within a few days.

## Scope

In scope: crypto primitives usage, manifest/op verification, the sync
relay's authz and parsers, the unlock daemon's IPC, the Raycast
extension's handling of secrets, supply-chain of released binaries.

Out of scope: physical access to an unlocked device, OS-level malware,
weak master passwords, metadata traffic analysis (documented in
docs/THREATMODEL.md).

## What we promise

- No bounty program (yet) — this is a solo open-source project.
- Credit in release notes if you want it.
- Honest advisories: if we ship a fix for your report, the advisory will
  say what it fixes.
