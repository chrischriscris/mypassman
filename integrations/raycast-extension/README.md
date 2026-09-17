# MyPassman — Raycast extension

A real Raycast view (searchable list + actions) on top of the `mypassman` CLI.
The simpler Script Commands live in `../raycast/`; this extension is the nicer
daily driver.

## Install

```bash
cd integrations/raycast-extension
npm install
npm run dev        # registers the extension with Raycast, then Ctrl-C
```

After `npm run dev` has loaded it once, "Search Vault" is a normal Raycast
command — you don't need dev mode running to use it. (For a permanent install
independent of this repo, build with `npm run build` and import the folder.)

## What it does

- **Search Vault** — `mypassman list --json`, kind icons, substring search
- **Enter** — *paste into the frontmost app*: the window closes, the CLI
  writes the concealed clipboard and synthesizes ⌘V (like a browser
  extension's autofill). On `totp` items Enter pastes the code instead
- **⌥T** — *type* the field as synthetic keystrokes: pasteboard never
  touched at all
- **⌥O** — paste TOTP code (non-totp items carrying 2FA)
- Clipboard still available as ⌘K actions — `⌘P` password, `⌘U` username,
  `⌘O` TOTP, `⌘L` url, `⌘N` card number, `⌘V` cvv — all concealed +
  auto-clear
- `⌘⇧L` locks the vault
- Vault locked? The empty view offers **Unlock Vault** — spawns the daemon,
  which pops Touch ID if `mypassman bio enroll` is done
- Resolves items by record id — no fuzzy-name ambiguity

## Security notes

- Secrets never enter the extension's JS: every copy action shells out to
  `mypassman get <id> --copy <field>` / `otp --copy`, which uses the concealed
  pasteboard + auto-clear janitor (`MPM_CLIP_TTL`, 45s default)
- Only names/kinds/ids cross the JSON boundary — fields stay sealed
- The binary path is hardcoded to `~/.local/bin/mypassman` — edit `MPM` in
  `src/list-items.tsx` if yours differs
- Paste/type autofill synthesizes CGEvents, which needs Accessibility
  ("post event") access for the app launching the CLI — Raycast, in this
  case. First use prompts once; if pastes silently no-op, check System
  Settings → Privacy & Security → Accessibility → Raycast
- Focus lands wherever your cursor was — the CLI waits `MPM_FILL_DELAY_MS`
  (default 200ms) for the target app to refocus after the window closes
