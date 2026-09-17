import { Action, ActionPanel, Icon, List, Toast, closeMainWindow, showHUD, showToast } from "@raycast/api";
import { useExec } from "@raycast/utils";
import { execFile, spawn } from "child_process";
import { promisify } from "util";

const MPM = "/Users/chus/.local/bin/mypassman";

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

// Every secret hand-off shells back to the CLI — the value goes straight
// from the daemon to the pasteboard/frontmost app and never enters this
// process. `closeMainWindow` first so focus returns to the target app
// before the synthetic keystrokes land.
async function fill(item: VaultItem, field: string, mode: "paste" | "type", otp: boolean) {
  await closeMainWindow({ clearRootSearch: true });
  try {
    const args = otp ? ["otp", item.id, `--${mode}`] : ["get", item.id, `--${mode}`, field];
    await run(args);
    await showHUD(`${otp ? "code" : field} ${mode === "paste" ? "pasted" : "typed"}`);
  } catch (e) {
    await showToast({
      style: Toast.Style.Failure,
      title: `Couldn't ${mode} ${otp ? "code" : field}`,
      message: e instanceof Error ? e.message : String(e),
    });
  }
}

async function copyField(item: VaultItem, field: string, otp: boolean) {
  const toast = await showToast({ style: Toast.Style.Animated, title: `Copying ${otp ? "code" : field}…` });
  try {
    const args = otp ? ["otp", item.id, "--copy"] : ["get", item.id, "--copy", field];
    await run(args);
    toast.style = Toast.Style.Success;
    toast.title = `${otp ? "code" : field} copied — auto-clears`;
  } catch (e) {
    toast.style = Toast.Style.Failure;
    toast.title = `Couldn't copy ${otp ? "code" : field}`;
    toast.message = e instanceof Error ? e.message : String(e);
  }
}

// Start the daemon detached — with `bio enroll` done this pops Touch ID.
// Poll list until the daemon answers (or give up after ~30s).
async function unlockVault(revalidate: () => void) {
  const toast = await showToast({ style: Toast.Style.Animated, title: "Unlocking — Touch ID" });
  spawn(MPM, ["daemon"], { detached: true, stdio: "ignore" }).unref();
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 750));
    try {
      await run(["list", "--json"]);
      toast.style = Toast.Style.Success;
      toast.title = "Vault unlocked";
      revalidate();
      return;
    } catch {
      // still locked — keep polling
    }
  }
  toast.style = Toast.Style.Failure;
  toast.title = "Still locked";
  toast.message = "Run `mypassman daemon` in a terminal to unlock with your password";
}

async function lockVault() {
  try {
    await run(["lock"]);
    await showToast({ style: Toast.Style.Success, title: "Vault locked" });
  } catch {
    await showToast({ style: Toast.Style.Failure, title: "Lock failed" });
  }
}

export default function Command() {
  const { data, isLoading, error, revalidate } = useExec(MPM, ["list", "--json"], {
    env: ENV.env,
    parseOutput: ({ stdout }) => JSON.parse(stdout) as VaultItem[],
  });

  if (error) {
    return (
      <List>
        <List.EmptyView
          icon={Icon.Lock}
          title="Vault is locked"
          description="Unlock once — the daemon serves copies for the rest of the session"
          actions={
            <ActionPanel>
              <Action title="Unlock Vault (Touch ID)" icon={Icon.LockUnlocked} onAction={() => unlockVault(revalidate)} />
            </ActionPanel>
          }
        />
      </List>
    );
  }

  return (
    <List isLoading={isLoading} searchBarPlaceholder="Search vault…">
      <List.EmptyView
        icon={Icon.Key}
        title="Vault is empty"
        description="Add items with `mypassman add login <name>` or `import --csv`"
        actions={
          <ActionPanel>
            <Action title="Lock Vault" icon={Icon.Lock} onAction={lockVault} />
          </ActionPanel>
        }
      />
      {(data ?? []).map((item) => {
        const isTotp = item.kind === "totp";
        const mainLabel = isTotp ? "Paste Code" : "Paste Password";
        return (
          <List.Item
            key={item.id}
            icon={KIND_ICON[item.kind] ?? Icon.Key}
            title={item.name}
            accessories={[{ tag: { value: item.kind || "item", color: "#6e6e73" } }]}
            actions={
              <ActionPanel>
                <Action
                  title={mainLabel}
                  icon={Icon.ArrowRightCircleFilled}
                  onAction={() => fill(item, "password", "paste", isTotp)}
                />
                <Action
                  title={isTotp ? "Type Code" : "Type Password"}
                  icon={Icon.Keyboard}
                  shortcut={{ modifiers: ["opt"], key: "t" }}
                  onAction={() => fill(item, "password", "type", isTotp)}
                />
                {!isTotp && (
                  <Action
                    title="Paste TOTP Code"
                    icon={Icon.Clock}
                    shortcut={{ modifiers: ["opt"], key: "o" }}
                    onAction={() => fill(item, "", "paste", true)}
                  />
                )}
                <ActionPanel.Section title="Clipboard">
                  <Action
                    title="Copy Password"
                    icon={Icon.Clipboard}
                    shortcut={{ modifiers: ["cmd"], key: "p" }}
                    onAction={() => copyField(item, "password", false)}
                  />
                  <Action
                    title="Copy Username"
                    icon={Icon.Person}
                    shortcut={{ modifiers: ["cmd"], key: "u" }}
                    onAction={() => copyField(item, "username", false)}
                  />
                  <Action
                    title="Copy TOTP Code"
                    icon={Icon.Clock}
                    shortcut={{ modifiers: ["cmd"], key: "o" }}
                    onAction={() => copyField(item, "", true)}
                  />
                  <Action
                    title="Copy URL"
                    icon={Icon.Link}
                    shortcut={{ modifiers: ["cmd"], key: "l" }}
                    onAction={() => copyField(item, "url", false)}
                  />
                  <Action
                    title="Copy Card Number"
                    icon={Icon.CreditCard}
                    shortcut={{ modifiers: ["cmd"], key: "n" }}
                    onAction={() => copyField(item, "number", false)}
                  />
                  <Action
                    title="Copy CVV"
                    icon={Icon.EyeDisabled}
                    shortcut={{ modifiers: ["cmd"], key: "v" }}
                    onAction={() => copyField(item, "cvv", false)}
                  />
                </ActionPanel.Section>
                <Action
                  title="Lock Vault"
                  icon={Icon.Lock}
                  style={Action.Style.Destructive}
                  shortcut={{ modifiers: ["cmd", "shift"], key: "l" }}
                  onAction={lockVault}
                />
              </ActionPanel>
            }
          />
        );
      })}
    </List>
  );
}
