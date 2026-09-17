import { Action, ActionPanel, Icon, List, Toast, showToast } from "@raycast/api";
import { useExec } from "@raycast/utils";
import { execFile, spawn } from "child_process";
import { promisify } from "util";

const MPM = "/Users/chus/.local/bin/mypassman";
const run = promisify(execFile);

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

// Copy actions call back into the CLI — the secret goes straight from the
// daemon to the concealed clipboard and never enters this process.
async function copyField(item: VaultItem, field: string) {
  const toast = await showToast({ style: Toast.Style.Animated, title: `Copying ${field}…` });
  try {
    await run(MPM, ["get", item.id, "--copy", field]);
    toast.style = Toast.Style.Success;
    toast.title = `${field} copied — auto-clears`;
  } catch (e) {
    toast.style = Toast.Style.Failure;
    toast.title = `Couldn't copy ${field}`;
    toast.message = e instanceof Error ? e.message : String(e);
  }
}

async function copyOtp(item: VaultItem) {
  const toast = await showToast({ style: Toast.Style.Animated, title: "Copying code…" });
  try {
    await run(MPM, ["otp", item.id, "--copy"]);
    toast.style = Toast.Style.Success;
    toast.title = "Code copied — auto-clears";
  } catch (e) {
    toast.style = Toast.Style.Failure;
    toast.title = "No TOTP on this item";
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
      await run(MPM, ["list", "--json"]);
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
    await run(MPM, ["lock"]);
    await showToast({ style: Toast.Style.Success, title: "Vault locked" });
  } catch {
    await showToast({ style: Toast.Style.Failure, title: "Lock failed" });
  }
}

export default function Command() {
  const { data, isLoading, error, revalidate } = useExec(MPM, ["list", "--json"], {
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
      {(data ?? []).map((item) => (
        <List.Item
          key={item.id}
          icon={KIND_ICON[item.kind] ?? Icon.Key}
          title={item.name}
          accessories={[{ tag: { value: item.kind || "item", color: "#6e6e73" } }]}
          actions={
            <ActionPanel>
              <Action
                title="Copy Password"
                icon={Icon.Clipboard}
                onAction={() => copyField(item, "password")}
              />
              <Action
                title="Copy Username"
                icon={Icon.Person}
                shortcut={{ modifiers: ["cmd"], key: "u" }}
                onAction={() => copyField(item, "username")}
              />
              <Action
                title="Copy TOTP Code"
                icon={Icon.Clock}
                shortcut={{ modifiers: ["cmd"], key: "t" }}
                onAction={() => copyOtp(item)}
              />
              <ActionPanel.Section title="More fields">
                <Action
                  title="Copy URL"
                  icon={Icon.Link}
                  shortcut={{ modifiers: ["cmd"], key: "l" }}
                  onAction={() => copyField(item, "url")}
                />
                <Action
                  title="Copy Card Number"
                  icon={Icon.CreditCard}
                  shortcut={{ modifiers: ["cmd"], key: "n" }}
                  onAction={() => copyField(item, "number")}
                />
                <Action
                  title="Copy CVV"
                  icon={Icon.EyeDisabled}
                  shortcut={{ modifiers: ["cmd"], key: "v" }}
                  onAction={() => copyField(item, "cvv")}
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
      ))}
    </List>
  );
}
