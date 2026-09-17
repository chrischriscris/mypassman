# Raycast script commands

1. Put the binary on PATH:
   `ln -sf "$PWD/../../target/release/mypassman" ~/.local/bin/mypassman`
   (or set `MPM_BIN` to an absolute path in the environment Raycast sees —
   simplest is the symlink).
2. Raycast → Settings → Extensions → Script Commands → "Add Script
   Directory" → pick this folder.
3. Commands appear as: "Copy Password", "Copy TOTP Code",
   "Copy Username", "Unlock Vault", "List Items".

Notes:
- Item names resolve by substring — "git" finds "github".
- Copy commands write the pasteboard with the concealed marker +
  auto-clear janitor (`MPM_CLIP_TTL`, default 45s).
- "Unlock Vault" starts the daemon; with `bio enroll` done it pops Touch
  ID, otherwise run `mpm daemon` in a terminal once (password prompt
  needs a tty).
- Everything goes through the daemon socket when it's alive — no
  password prompts per command.
