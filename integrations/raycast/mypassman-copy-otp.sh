#!/bin/bash

# @raycast.schemaVersion 1
# @raycast.title Copy TOTP Code
# @raycast.mode compact
# @raycast.packageName mypassman
# @raycast.argument1 { "type": "text", "placeholder": "item name" }
# @raycast.description Copy the current authenticator code (concealed, auto-clears)

BIN="${MPM_BIN:-$HOME/.local/bin/mypassman}"
[ -x "$BIN" ] || BIN="$(command -v mypassman || true)"
[ -x "$BIN" ] || { echo "mypassman not found — symlink the binary to ~/.local/bin/mypassman"; exit 1; }

export MPM_NO_BIO=1  # never pop Touch ID from a script — unlock via Unlock Vault

out=$("$BIN" otp "$1" --copy 2>&1) || { echo "✗ $out"; exit 1; }
echo "✓ code copied — clears in ${MPM_CLIP_TTL:-45}s"
