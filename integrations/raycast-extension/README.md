# MyPassman — Raycast extension

A real Raycast view (searchable list + detail panel + actions) on top of the
`mypassman` CLI. The simpler Script Commands live in `../raycast/`; this
extension is the nicer daily driver.

## Install

```bash
cd integrations/raycast-extension
npm install
npm run dev        # registers the extension with Raycast, then Ctrl-C
```

After `npm run dev` has loaded it once, "Search Vault" is a normal Raycast
command — you don't need dev mode running to use it. (For a permanent install
independent of this repo, build with `npm run build` and import the folder.)

The binary path defaults to `~/.local/bin/mypassman` — change it in the
extension's preferences ("mypassman Binary Path") if yours lives elsewhere.

## What it does

- **Search Vault** — `mypassman list --json`; kind icons, per-kind subtitles
  (username / issuer / holder / endpoint), hostname accessories, live TOTP
  countdown tags. Searches name + username + domain + issuer + kind
- **Detail panel** (⌘D to toggle) — all non-secret metadata; secret fields
  listed as `••••••••` so you see what's there without the value
- **Kind filter** — dropdown in the search bar
- **Enter** — pastes the primary field into the frontmost app (password /
  code / card number / key…). Waits for a fresh TOTP code if <5s remain.
  If the primary field is missing the next available field is offered —
  actions only appear for fields that actually exist
- **⌥T** — type the primary field (zero clipboard)
- **⌥⇧T** — *Fill Username + Password*: types `username⇥password` on
  logins. Deliberately opt-in — Tab navigation fails on some forms and
  would concatenate the password into the username field
- **⌥O** — paste TOTP code (logins carrying 2FA)
- **Clipboard section** — `Copy {field}` for every field present, all
  concealed + auto-clear (`⌥P` password, `⌥U` username, `⌘O` TOTP code)
- **Vault section** — `⌘⇧O` Open URL, `⌘R` refresh, `⌘⇧L` lock
- **Recent** — last 5 filled/copied items pinned to the top (record ids only,
  in Raycast LocalStorage)
- Vault locked? The empty view offers **Unlock Vault** — spawns the daemon,
  which pops Touch ID if `mypassman bio enroll` is done. The Touch ID sheet
  takes focus and Raycast's window hides — expected, once per daemon
  session; the extension tries to reopen itself afterward. All other calls
  run with `MPM_NO_BIO=1` so they can never trigger the prompt
- Error states distinguish locked vault / missing binary / other failures
- Resolves items by record id — no fuzzy-name ambiguity

## Security notes

- Secrets never enter the extension's JS: every fill/copy action shells out
  to `mypassman get <id>` / `otp <id>` (`--paste`/`--type`/`--copy`), which
  uses the concealed pasteboard + auto-clear janitor (`MPM_CLIP_TTL`, 45s
  default) or synthetic keystrokes with no clipboard at all
- `list --json` carries only metadata: kind, name, record id, field *names*
  (presence is metadata, not a secret), and values of fields explicitly
  classified non-secret (username, url, issuer, holder, endpoint…). Unknown
  field tags default to secret and are never emitted
- Paste posts `⌘V` through System Events (osascript) — needs **Automation**
  consent for the launching app (one-time prompt). Typing uses CGEvent
  keystrokes — needs **Accessibility** ("post event") access instead
- Fills are bound to the app that was frontmost when Raycast opened: if
  focus moved elsewhere by the time the window closes, the fill aborts
  rather than land a secret in the wrong window. `__dopaste` also
  re-verifies the pasteboard still holds the exact copied value before
  posting — overlapping fills or a cleared clipboard abort instead of
  pasting the wrong thing, and a failed paste clears our payload
- Focus lands wherever your cursor was — the extension polls
  `getFrontmostApplication` until Raycast yields focus before spawning the
  fill, and the CLI additionally waits `MPM_FILL_DELAY_MS` (default 350ms)
  before posting events
- The daemon idle timeout is the built-in default: 900s
