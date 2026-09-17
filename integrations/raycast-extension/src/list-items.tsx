import {
  Action,
  ActionPanel,
  Color,
  Icon,
  List,
  LocalStorage,
  Toast,
  closeMainWindow,
  getFrontmostApplication,
  getPreferenceValues,
  open,
  showHUD,
  showToast,
} from "@raycast/api";
import { useExec } from "@raycast/utils";
import { execFile, spawn } from "child_process";
import { homedir } from "os";
import { promisify } from "util";
import { useEffect, useState } from "react";

const prefs = getPreferenceValues<{ binaryPath?: string }>();
const MPM = (prefs.binaryPath || "~/.local/bin/mypassman").replace(/^~/, homedir());

// MPM_NO_BIO: the LAContext Touch ID sheet steals focus and closes the
// Raycast window — so interactive calls must NEVER trigger it. A locked
// vault fails fast instead; only the explicit "Unlock Vault" action
// (which spawns the daemon without this env) pops Touch ID.
const ENV = { env: { ...process.env, MPM_NO_BIO: "1" } };
const execFileP = promisify(execFile);
const run = (args: string[]) => execFileP(MPM, args, ENV);

interface VaultItem {
  kind: string;
  name: string;
  id: string;
  fields: string[];
  meta: Record<string, string>;
}

const KIND_ICON: Record<string, Icon> = {
  login: Icon.Globe,
  card: Icon.CreditCard,
  secret: Icon.Lock,
  apikey: Icon.Terminal,
  totp: Icon.Clock,
  identity: Icon.Person,
  sshkey: Icon.Key,
};

const FIELD_LABEL: Record<string, string> = {
  password: "Password",
  username: "Username",
  number: "Card Number",
  exp: "Expiry",
  cvv: "CVV",
  holder: "Cardholder",
  pin: "PIN",
  key: "API Key",
  secret: "Secret",
  endpoint: "Endpoint",
  env: "Env",
  expires: "Expires",
  totp_secret: "TOTP Secret",
  issuer: "Issuer",
  url: "URL",
  notes: "Notes",
  text: "Text",
  full_name: "Full Name",
  email: "Email",
  private: "Private Key",
  public: "Public Key",
};
// config noise — shown in detail, not worth a copy action
const NO_COPY = new Set(["digits", "period", "algo", "issuer", "expires"]);
const label = (f: string) => FIELD_LABEL[f] ?? f;

const SECRET_BY_KIND: Record<string, string> = {
  login: "password",
  card: "number",
  apikey: "key",
  secret: "text",
  sshkey: "private",
  identity: "email",
};

function subtitle(item: VaultItem): string {
  switch (item.kind) {
    case "login":
      return item.meta.username ?? "";
    case "totp":
      return item.meta.issuer ?? "";
    case "card":
      return item.meta.holder ?? "";
    case "apikey":
      return item.meta.endpoint ?? item.meta.env ?? "";
    case "identity":
      return item.meta.email ?? item.meta.full_name ?? "";
    default:
      return "";
  }
}

function hostname(url?: string): string {
  if (!url) return "";
  return url
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .split(/[/?#]/)[0];
}

// seconds until the TOTP code rolls — computable locally because period is
// non-secret metadata; the code itself never leaves the CLI
function totpLeft(item: VaultItem, now: number): number | null {
  const p = parseInt(item.meta.period ?? "", 10);
  if (!p || p <= 0) return null;
  return p - (Math.floor(now / 1000) % p);
}

const hasTotp = (item: VaultItem) => item.fields.includes("totp_secret");

function detail(item: VaultItem) {
  const secretNames = item.fields.filter((f) => !(f in item.meta));
  return (
    <List.Item.Detail
      metadata={
        <List.Item.Detail.Metadata>
          <List.Item.Detail.Metadata.Label title="Name" text={item.name} />
          <List.Item.Detail.Metadata.Label title="Kind" text={item.kind || "item"} />
          {Object.entries(item.meta).map(([k, v]) =>
            k === "url" ? (
              <List.Item.Detail.Metadata.Link key={k} title="URL" text={v} target={v} />
            ) : (
              <List.Item.Detail.Metadata.Label key={k} title={label(k)} text={v} />
            ),
          )}
          {secretNames.length > 0 && <List.Item.Detail.Metadata.Separator />}
          {secretNames.map((f) => (
            <List.Item.Detail.Metadata.Label key={f} title={label(f)} text="••••••••" />
          ))}
        </List.Item.Detail.Metadata>
      }
    />
  );
}

// closeMainWindow resolves before macOS finishes moving focus back to the
// target app — firing ⌘V/keystrokes during that gap loses the fill. Poll
// until Raycast is no longer frontmost (bounded, in case it never leaves).
async function waitForFocus() {
  for (let i = 0; i < 50; i++) {
    try {
      const app = await getFrontmostApplication();
      if (app.bundleId !== "com.raycast.macos" && app.name !== "Raycast") return;
    } catch {
      return; // can't determine — don't stall the fill
    }
    await new Promise((r) => setTimeout(r, 50));
  }
}

// Every secret hand-off shells back to the CLI — the value goes straight
// from the daemon to the pasteboard/frontmost app and never enters this
// process. `closeMainWindow` first so focus returns to the target app
// before the synthetic keystrokes land.
const fail = async (title: string, e: unknown, closed: boolean) => {
  const msg = e instanceof Error ? e.message : String(e);
  // once the window is closed only HUDs render; toasts need it open
  if (closed) await showHUD(`⚠ ${title}: ${msg.split("\n").pop()}`);
  else
    await showToast({
      style: Toast.Style.Failure,
      title,
      message: /unlock/i.test(msg) ? "Vault locked — run Unlock Vault first" : msg,
    });
};

let fillInFlight = false; // overlapping fills can swap clipboard contents
async function fill(item: VaultItem, fields: string[], mode: "paste" | "type", otp: boolean) {
  if (fillInFlight) {
    return showToast({ style: Toast.Style.Failure, title: "A fill is already in progress" });
  }
  fillInFlight = true;
  try {
    await fillInner(item, fields, mode, otp);
  } finally {
    fillInFlight = false;
  }
}

async function fillInner(item: VaultItem, fields: string[], mode: "paste" | "type", otp: boolean) {
  // paste mode is single-field; multi-field fill is type-only
  const useFields = mode === "paste" ? fields.slice(0, 1) : fields;
  const what = otp ? "code" : useFields.join(" ⇥ ");
  // a code rolling in <5s usually dies before the form submits — wait for it
  const left = otp ? totpLeft(item, Date.now()) : null;
  const wait = left !== null && left <= 5 ? left * 1000 + 400 : 0;
  if (wait > 0) {
    const t = await showToast({ style: Toast.Style.Animated, title: "Waiting for fresh code…" });
    await new Promise((r) => setTimeout(r, wait));
    t.hide();
  }
  // the app that was frontmost when Raycast opened is the fill's intended
  // destination — verify it's still frontmost after our window closes so
  // a focus jump can't carry a secret somewhere else
  let intended = "";
  try {
    intended = (await getFrontmostApplication()).bundleId ?? "";
  } catch {}
  // Phase 1 — everything that can fail while the window is still open:
  // CGEvent permission check for typing; the concealed clipboard write
  // for paste (its keystroke goes through System Events instead).
  try {
    if (mode === "type") await run(["__preflight"]);
    if (mode === "paste") {
      await run(otp ? ["otp", item.id, "--copy"] : ["get", item.id, "--copy", useFields[0]]);
    }
  } catch (e) {
    return fail(`Couldn't ${mode} ${what}`, e, false);
  }
  // Phase 2 — close, let focus return, then post the event(s).
  await closeMainWindow({ clearRootSearch: true });
  await waitForFocus();
  let target = "";
  let targetOk = true;
  try {
    const app = await getFrontmostApplication();
    target = app.name;
    targetOk = !intended || !app.bundleId || app.bundleId === intended;
  } catch {}
  if (!targetOk) {
    // the copy stays sealed — the janitor clears it within the clip TTL;
    // better a missed fill than a password in the wrong window
    return showHUD(`⚠ Focus moved to ${target} — fill aborted`);
  }
  try {
    if (mode === "paste") {
      // __dopaste re-verifies the pasteboard still holds this exact value
      await run(["__dopaste", item.id, otp ? "--otp" : useFields[0]]);
    } else {
      await run(
        otp
          ? ["otp", item.id, "--type"]
          : ["get", item.id, ...useFields.flatMap((f) => ["--type", f])],
      );
    }
    await showHUD(`${what} ${mode === "paste" ? "pasted" : "typed"}${target ? ` → ${target}` : ""}`);
    bumpRecent(item.id);
  } catch (e) {
    await fail(`Couldn't ${mode} ${what}`, e, true);
  }
}

async function copyField(item: VaultItem, field: string, otp: boolean) {
  const toast = await showToast({ style: Toast.Style.Animated, title: `Copying ${otp ? "code" : label(field)}…` });
  try {
    const args = otp ? ["otp", item.id, "--copy"] : ["get", item.id, "--copy", field];
    await run(args);
    toast.style = Toast.Style.Success;
    toast.title = `${otp ? "code" : label(field)} copied — auto-clears`;
    bumpRecent(item.id);
  } catch (e) {
    toast.style = Toast.Style.Failure;
    toast.title = `Couldn't copy ${otp ? "code" : label(field)}`;
    toast.message = e instanceof Error ? e.message : String(e);
  }
}

const RECENT_KEY = "mypassman-recent";
async function bumpRecent(id: string) {
  try {
    const cur = JSON.parse((await LocalStorage.getItem<string>(RECENT_KEY)) ?? "[]") as string[];
    const next = [id, ...cur.filter((x) => x !== id)].slice(0, 5);
    await LocalStorage.setItem(RECENT_KEY, JSON.stringify(next));
  } catch {
    // recents are cosmetic — never block an action over it
  }
}

// Start the daemon detached — with `bio enroll` done this pops Touch ID.
// Poll list until the daemon answers (or give up after ~30s).
async function unlockVault(revalidate: () => void) {
  const toast = await showToast({ style: Toast.Style.Animated, title: "Unlocking — Touch ID" });
  // no MPM_IDLE_TTL override — daemon's built-in default is 900s
  spawn(MPM, ["daemon"], { detached: true, stdio: "ignore" }).unref();
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 750));
    try {
      await run(["list", "--json"]);
      toast.style = Toast.Style.Success;
      toast.title = "Vault unlocked";
      revalidate();
      try {
        // land the user back in the list if the window hid behind the prompt
        await open("raycast://extensions/chus/mypassman/list-items");
      } catch {
        // deeplink best-effort — the HUD still confirms unlock
      }
      return;
    } catch {
      // still locked — keep polling
    }
  }
  toast.style = Toast.Style.Failure;
  toast.title = "Still locked";
  toast.message = "Run `mypassman daemon` in a terminal to unlock with your password";
}

async function lockVault(revalidate: () => void) {
  try {
    await run(["lock"]);
    await showToast({ style: Toast.Style.Success, title: "Vault locked" });
    revalidate(); // daemon is gone — list flips to the locked state
  } catch {
    await showToast({ style: Toast.Style.Failure, title: "Lock failed" });
  }
}

function RowActions({
  item,
  appName,
  revalidate,
  toggleDetail,
}: {
  item: VaultItem;
  appName: string;
  revalidate: () => void;
  toggleDetail: () => void;
}) {
  const isTotp = item.kind === "totp";
  const preferred = SECRET_BY_KIND[item.kind];
  const primary = preferred && item.fields.includes(preferred) ? preferred : item.fields[0];
  const loginPair = item.fields.includes("username") && item.fields.includes("password");
  const primaryAction = isTotp
    ? { title: `Paste Code into ${appName}`, run: () => fill(item, [], "paste", true) }
    : primary
      ? { title: `Paste ${label(primary)} into ${appName}`, run: () => fill(item, [primary], "paste", false) }
      : null;

  const copyable = item.fields.filter((f) => !NO_COPY.has(f));
  return (
    <ActionPanel>
      <ActionPanel.Section title="Fill">
        {primaryAction && (
          <Action title={primaryAction.title} icon={Icon.ArrowRightCircleFilled} onAction={primaryAction.run} />
        )}
        {!isTotp && primary && (
          <Action
            title={`Type ${label(primary)}`}
            icon={Icon.Keyboard}
            shortcut={{ modifiers: ["opt"], key: "t" }}
            onAction={() => fill(item, [primary], "type", false)}
          />
        )}
        {/* u⇥p typed fill is opt-in — Tab navigation fails on some forms and
            would concatenate the password into the username field */}
        {item.kind === "login" && loginPair && (
          <Action
            title={`Fill Username + Password into ${appName}`}
            icon={Icon.Keyboard}
            shortcut={{ modifiers: ["opt", "shift"], key: "t" }}
            onAction={() => fill(item, ["username", "password"], "type", false)}
          />
        )}
        {!isTotp && hasTotp(item) && (
          <Action
            title={`Paste TOTP Code into ${appName}`}
            icon={Icon.Clock}
            shortcut={{ modifiers: ["opt"], key: "o" }}
            onAction={() => fill(item, [], "paste", true)}
          />
        )}
      </ActionPanel.Section>
      <ActionPanel.Section title="Clipboard">
        {hasTotp(item) && (
          <Action
            title="Copy TOTP Code"
            icon={Icon.Clock}
            shortcut={{ modifiers: ["cmd"], key: "o" }}
            onAction={() => copyField(item, "", true)}
          />
        )}
        {copyable.map((f) => (
          <Action
            key={f}
            title={`Copy ${label(f)}`}
            icon={Icon.Clipboard}
            shortcut={
              f === "password"
                ? { modifiers: ["opt"], key: "p" }
                : f === "username"
                  ? { modifiers: ["opt"], key: "u" }
                  : undefined
            }
            onAction={() => copyField(item, f, false)}
          />
        ))}
      </ActionPanel.Section>
      <ActionPanel.Section title="Vault">
        {item.meta.url && (
          <Action.OpenInBrowser
            title="Open URL"
            icon={Icon.Link}
            shortcut={{ modifiers: ["cmd", "shift"], key: "o" }}
            url={/^https?:\/\//.test(item.meta.url) ? item.meta.url : `https://${item.meta.url}`}
          />
        )}
        <Action
          title="Toggle Details"
          icon={Icon.Sidebar}
          shortcut={{ modifiers: ["cmd"], key: "d" }}
          onAction={toggleDetail}
        />
        <Action title="Refresh" icon={Icon.ArrowClockwise} shortcut={{ modifiers: ["cmd"], key: "r" }} onAction={revalidate} />
        <Action
          title="Lock Vault"
          icon={Icon.Lock}
          style={Action.Style.Destructive}
          shortcut={{ modifiers: ["cmd", "shift"], key: "l" }}
          onAction={() => lockVault(revalidate)}
        />
      </ActionPanel.Section>
    </ActionPanel>
  );
}

const KINDS = ["login", "card", "totp", "apikey", "secret", "identity", "sshkey"];

export default function Command() {
  const { data, isLoading, error, revalidate } = useExec(MPM, ["list", "--json"], {
    env: ENV.env,
    // parseOutput runs even on non-zero exits — surface stderr ("unlock
    // failed"…) instead of letting JSON.parse("") mask the real error
    parseOutput: ({ stdout, stderr, exitCode }) => {
      if (exitCode !== 0 || !stdout.trim()) {
        throw new Error(stderr.trim() || `mypassman exited ${exitCode}`);
      }
      return JSON.parse(stdout) as VaultItem[];
    },
  });
  const [kindFilter, setKindFilter] = useState("all");
  const [showDetail, setShowDetail] = useState(true);
  const [appName, setAppName] = useState("frontmost app");
  const [recentIds, setRecentIds] = useState<string[]>([]);
  const [, setTick] = useState(0); // 1s tick → TOTP countdowns stay live

  useEffect(() => {
    getFrontmostApplication()
      .then((a) => setAppName(a.name))
      .catch(() => {});
    LocalStorage.getItem<string>(RECENT_KEY).then((v) => {
      try {
        setRecentIds(JSON.parse(v ?? "[]"));
      } catch {}
    });
    const t = setInterval(() => setTick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, []);

  if (error) {
    const msg = error.message ?? String(error);
    const locked = /unlock|password|denied/i.test(msg);
    const missing = /ENOENT|spawn.*fail|not found|not a file/i.test(msg);
    return (
      <List>
        <List.EmptyView
          icon={locked ? Icon.Lock : missing ? Icon.Terminal : Icon.ExclamationMark}
          title={
            locked ? "Vault is locked" : missing ? `mypassman not found at ${MPM}` : "Something went wrong"
          }
          description={
            locked
              ? "Unlock with Touch ID — Raycast will hide while macOS prompts you; reopen with your hotkey."
              : missing
                ? "Point the binaryPath preference at your mypassman build."
                : msg
          }
          actions={
            <ActionPanel>
              {locked ? (
                <Action title="Unlock Vault (Touch ID)" icon={Icon.LockUnlocked} onAction={() => unlockVault(revalidate)} />
              ) : (
                <Action title="Retry" icon={Icon.ArrowClockwise} onAction={revalidate} />
              )}
            </ActionPanel>
          }
        />
      </List>
    );
  }

  const items = (data ?? []).filter((i) => kindFilter === "all" || i.kind === kindFilter);
  const recent = items.filter((i) => recentIds.includes(i.id)).sort((a, b) => recentIds.indexOf(a.id) - recentIds.indexOf(b.id));
  const now = Date.now();

  const row = (item: VaultItem) => {
    const left = hasTotp(item) ? totpLeft(item, now) : null;
    return (
      <List.Item
        key={item.id}
        icon={KIND_ICON[item.kind] ?? Icon.Key}
        title={item.name}
        subtitle={subtitle(item)}
        keywords={[item.name, subtitle(item), hostname(item.meta.url), item.meta.issuer ?? "", item.kind]}
        accessories={[
          ...(item.meta.url ? [{ text: hostname(item.meta.url) }] : []),
          ...(hasTotp(item) ? [{ icon: Icon.Clock, tooltip: "has TOTP" }] : []),
          ...(left !== null
            ? [{ tag: { value: `${left}s`, color: left <= 5 ? Color.Red : Color.SecondaryText } }]
            : []),
        ]}
        detail={detail(item)}
        actions={<RowActions item={item} appName={appName} revalidate={revalidate} toggleDetail={() => setShowDetail((s) => !s)} />}
      />
    );
  };

  return (
    <List
      isLoading={isLoading}
      isShowingDetail={showDetail}
      searchBarPlaceholder="Search vault — name, username, domain…"
      searchBarAccessory={
        <List.Dropdown tooltip="Filter by kind" value={kindFilter} onChange={setKindFilter}>
          <List.Dropdown.Item title="All kinds" value="all" />
          {KINDS.map((k) => (
            <List.Dropdown.Item key={k} title={k} value={k} />
          ))}
        </List.Dropdown>
      }
    >
      <List.EmptyView
        icon={Icon.Key}
        title={kindFilter === "all" ? "Vault is empty" : `No ${kindFilter} items`}
        description="Add items with `mypassman add` or `import --csv` / `--otpauth`"
        actions={
          <ActionPanel>
            <Action title="Refresh" icon={Icon.ArrowClockwise} onAction={revalidate} />
            <Action.CopyToClipboard title="Copy add command" content="mypassman add login " />
          </ActionPanel>
        }
      />
      {recent.length > 0 && <List.Section title="Recent">{recent.map(row)}</List.Section>}
      <List.Section title={recent.length > 0 ? "All Items" : undefined}>{items.map(row)}</List.Section>
    </List>
  );
}
