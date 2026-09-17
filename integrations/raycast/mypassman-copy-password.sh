#!/bin/bash

# @raycast.schemaVersion 1
# @raycast.title Copy Password
# @raycast.mode compact
# @raycast.packageName mypassman
# @raycast.argument1 { "type": "text", "placeholder": "item name" }
# @raycast.description Copy an item's password to the clipboard (concealed, auto-clears in 45s)

BIN="${MPM_BIN:-$HOME/.local/bin/mypassman}"
[ -x "$BIN" ] || BIN="$(command -v mypassman || true)"
[ -x "$BIN" ] || { echo "mypassman not found — symlink the binary to ~/.local/bin/mypassman"; exit 1; }

export MPM_NO_BIO=1  # never pop Touch ID from a script — unlock via Unlock Vault

out=$("$BIN" get "$1" -c password 2>&1) || { echo "✗ $out"; exit 1; }
echo "✓ password copied — clears in ${MPM_CLIP_TTL:-45}s"
