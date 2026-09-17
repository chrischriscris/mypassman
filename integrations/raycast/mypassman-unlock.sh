#!/bin/bash

# @raycast.schemaVersion 1
# @raycast.title Unlock Vault (start daemon)
# @raycast.mode compact
# @raycast.packageName mypassman
# @raycast.description Start the unlock daemon — Touch ID prompt if enrolled. One unlock per session.

BIN="${MPM_BIN:-$HOME/.local/bin/mypassman}"
[ -x "$BIN" ] || BIN="$(command -v mypassman || true)"
[ -x "$BIN" ] || { echo "mypassman not found — symlink the binary to ~/.local/bin/mypassman"; exit 1; }

if "$BIN" list >/dev/null 2>&1; then
    echo "already unlocked"
    exit 0
fi

# daemon runs until idle TTL or `mpm lock` — detach so Raycast doesn't wait
MPM_IDLE_TTL="${MPM_IDLE_TTL:-3600}" nohup "$BIN" daemon >/dev/null 2>&1 &
sleep 0.5
if "$BIN" list >/dev/null 2>&1; then
    echo "unlock prompt sent — Touch ID if enrolled"
else
    echo "daemon starting — if no Touch ID appears, run 'mpm daemon' in a terminal (password unlock)"
fi
