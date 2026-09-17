#!/bin/bash

# @raycast.schemaVersion 1
# @raycast.title List Items
# @raycast.mode fullOutput
# @raycast.packageName mypassman
# @raycast.description List vault items (names only — secrets never shown)

BIN="${MPM_BIN:-$HOME/.local/bin/mypassman}"
[ -x "$BIN" ] || BIN="$(command -v mypassman || true)"
[ -x "$BIN" ] || { echo "mypassman not found — symlink the binary to ~/.local/bin/mypassman"; exit 1; }

export MPM_NO_BIO=1  # never pop Touch ID from a script — unlock via Unlock Vault

"$BIN" list 2>&1
