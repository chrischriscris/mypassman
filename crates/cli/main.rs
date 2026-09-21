//! mypassman CLI — v0: init/add/get/list/rm/devices on a single device.
//! Daemon + agent mode land at M2.

use clap::{Parser, Subcommand};
use mpm_core::item::{tag, Item, ItemKind};
#[cfg(target_os = "macos")]
use mpm_core::manifest::SLOT_BIOMETRIC;
use mpm_core::manifest::{WrapSlot, SLOT_PASSWORD, SLOT_RECOVERY};
use mpm_core::{gen, recovery, CoreError, Manifest, Vault, HASH_LEN};
use mpm_crypto::kdf::{self, KdfParams};
use mpm_crypto::keys::{DeviceKey, KeyBundle};
#[cfg(target_os = "macos")]
mod autofill;
#[cfg(target_os = "macos")]
mod bio;
mod daemon;
mod sync;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const DEVICE_KDF_CAP_KIB: u32 = 1_048_576; // 1 GiB desktop cap

#[derive(Parser)]
#[command(
    name = "mypassman",
    version,
    about = "local-first E2EE password manager"
)]
struct Cli {
    /// Vault directory (default ~/.mypassman/vault, or $MPM_VAULT)
    #[arg(long, global = true)]
    vault: Option<PathBuf>,
    /// Unlock with recovery code instead of master password
    #[arg(long, global = true)]
    recovery: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault
    Init,
    /// Add an item: mypassman add login github -f username=me [-f password=..]
    Add {
        kind: String,
        name: String,
        /// field=value pairs; secret fields are prompted if omitted
        #[arg(short = 'f', long = "field")]
        fields: Vec<String>,
    },
    /// Show an item (secrets masked unless -s)
    Get {
        name: String,
        /// reveal secret fields in output
        #[arg(short, long)]
        show: bool,
        /// copy one field to clipboard (e.g. -c password)
        #[arg(short, long)]
        copy: Option<String>,
        /// copy field then simulate ⌘V into the frontmost app (macOS)
        #[arg(long)]
        paste: Option<String>,
        /// type field(s) as synthetic keystrokes, Tab between — repeat for
        /// multi-field fills: --type username --type password (macOS)
        #[arg(long = "type")]
        r#type: Vec<String>,
    },
    /// List items (names + kinds only — fields stay sealed)
    #[command(alias = "ls")]
    List {
        /// Emit a JSON array of {kind, name, id} — for integrations
        #[arg(long)]
        json: bool,
    },
    /// Tombstone an item
    Rm { name: String },
    /// Show an item's version history (replays the op log; never prints
    /// secret values — only which fields changed)
    History {
        name: String,
        /// Emit a JSON array of versions — for integrations
        #[arg(long)]
        json: bool,
    },
    /// Show enrolled devices
    Devices,
    /// Change the master password — re-wraps the vault keys under a new
    /// password-derived KEK. The DEK itself does not rotate (that happens
    /// on `pair revoke`); copies of this manifest already exfiltrated stay
    /// openable by the old password — only future access needs the new one.
    Passwd,
    /// Recovery kit management
    Recovery {
        #[command(subcommand)]
        sub: RecoveryCmd,
    },
    /// Generate a password or passphrase (no vault needed)
    Gen {
        /// length (charset mode, default 20) or word count (--passphrase, default 6)
        #[arg(short, long)]
        len: Option<usize>,
        /// passphrase mode: N words joined by '-'
        #[arg(short, long)]
        passphrase: bool,
        /// alnum only (no symbols)
        #[arg(long)]
        no_symbols: bool,
        /// copy to clipboard instead of printing
        #[arg(short, long)]
        copy: bool,
    },
    /// Current TOTP code for an item holding a totp_secret (any kind —
    /// a login can carry its own 2FA secret)
    Otp {
        name: String,
        /// copy code to clipboard instead of printing
        #[arg(short, long)]
        copy: bool,
        /// copy code then simulate ⌘V into the frontmost app (macOS)
        #[arg(long)]
        paste: bool,
        /// type code as synthetic keystrokes — clipboard never touched (macOS)
        #[arg(long = "type")]
        r#type: bool,
    },
    /// Edit fields of an existing item (refuses to create — use `add`)
    Edit {
        name: String,
        #[arg(short = 'f', long = "field")]
        fields: Vec<String>,
    },
    /// Run a command with secrets injected as env vars:
    ///   mpm run -i openai/key=OPENAI_API_KEY -i gh/key=GH_TOKEN -- npm publish
    Run {
        /// item:field=ENV_VAR mappings
        #[arg(short = 'i', long = "inject")]
        inject: Vec<String>,
        /// command + args
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// (internal) clipboard janitor — spawned detached, clears clipboard
    /// after TTL iff it still holds our payload. Hash arrives on stdin.
    #[command(hide = true, name = "__clipclear")]
    Clipclear,
    /// (internal) check/request Accessibility post-event access — launchers
    /// call this while their window is still up so failures are visible
    #[command(hide = true, name = "__preflight")]
    Preflight,
    /// (internal) verify the pasteboard still holds <id>'s <field> — or
    /// the current code with --otp — then post ⌘V into the frontmost app
    #[command(hide = true, name = "__dopaste")]
    Dopaste {
        id: String,
        field: Option<String>,
        /// verify against the item's current TOTP code instead of a field
        #[arg(long)]
        otp: bool,
    },
    /// (internal) exit 0 iff the unlock daemon answers PING — locked
    /// launchers poll this instead of `list`, which would run a doomed
    /// standalone unlock (Argon2 on an empty password) every poll
    #[command(hide = true, name = "__ping")]
    Ping,
    /// Export all items to a passphrase-sealed portable file (MPMEXP).
    /// The export passphrase is prompted (or $MPM_EXPORT_PASSWORD).
    Export { path: PathBuf },
    /// Import items. Default: an MPMEXP sealed export; --csv reads a
    /// Bitwarden/1Password-style CSV export (login/card/note rows);
    /// --otpauth reads plaintext otpauth:// URI lists (Ente, Aegis, 2FAS).
    Import {
        path: PathBuf,
        /// treat input as CSV instead of MPMEXP
        #[arg(long)]
        csv: bool,
        /// treat input as newline/comma-separated otpauth:// URIs
        #[arg(long)]
        otpauth: bool,
        /// show what would happen — writes nothing, no unlock needed for CSV
        #[arg(long)]
        dry_run: bool,
    },
    /// Verified backup: replay-checks the vault, then copies MANIFEST+ops
    /// into <dest>/mypassman-backup-<ts>-<vaultid>. It's already ciphertext.
    Backup { dest: PathBuf },
    /// Restore a backup directory into --vault (which must not exist yet),
    /// then replay-verify it before accepting.
    Restore { src: PathBuf },
    /// Run the unlock daemon (unix): one Argon2 unlock, then commands
    /// served over a private socket until the idle TTL lapses.
    Daemon {
        /// idle seconds before the daemon locks itself (default 900,
        /// or $MPM_IDLE_TTL)
        #[arg(long)]
        idle_ttl: Option<u64>,
    },
    /// Lock now: tell a running daemon to drop the vault and exit
    Lock,
    /// Biometric unlock (Touch ID on macOS): enroll/remove
    Bio {
        #[command(subcommand)]
        sub: BioCmd,
    },
    /// Sync with a syncd relay: pull foreign ops, push ours, reconcile the
    /// manifest. No unlock needed — everything moved is ciphertext.
    Sync {
        #[command(subcommand)]
        sub: Option<SyncCmd>,
    },
    /// Device pairing: invite a new device, approve it, finish enrollment
    Pair {
        #[command(subcommand)]
        sub: PairCmd,
    },
}

#[derive(Subcommand)]
enum RecoveryCmd {
    /// Mint a new recovery code (requires master password); invalidates the old kit
    Rotate,
}

#[derive(Subcommand)]
enum BioCmd {
    /// Store a Touch ID-gated KEK in the Keychain; unlocks then prompt for
    /// biometrics instead of the master password. Password always remains
    /// as fallback.
    Enroll,
    /// Remove biometric unlock: deletes the Keychain item and wrap slot
    Off,
}

#[derive(Subcommand)]
enum SyncCmd {
    /// Bootstrap this vault onto a syncd server (first device only); stores
    /// the admin token + this device's read/write tokens locally.
    Init {
        /// syncd base URL, e.g. https://syncd.example.com or http://localhost:8787
        url: String,
        /// the SETUP_KEY wrangler secret from the deployment
        #[arg(long)]
        setup_key: String,
    },
}

#[derive(Subcommand)]
enum PairCmd {
    /// Mint a short-lived invite for a new device (owner side).
    /// Prints <vault_id>.<code> — the vault id routes the join request.
    Invite {
        /// also print a QR encoding `mpm://pair?server=…&invite=…`
        #[arg(long)]
        qr: bool,
    },
    /// List devices waiting for approval
    Pending,
    /// Approve a pending device (id prefix) — re-signs and pushes the manifest
    Approve { device: String },
    /// Decline a pending join request (id prefix)
    Decline { device: String },
    /// On the new device: request enrollment with <url> <invite>
    /// (invite = <vault_id>.<code> printed by `pair invite`)
    Join {
        url: String,
        invite: String,
        /// label the approver sees, e.g. "work macbook"
        #[arg(long, default_value = "new device")]
        name: String,
    },
    /// On the new device: exchange the invite for tokens after approval
    Finish,
    /// Revoke an enrolled device (id prefix) — owner re-signs the manifest
    /// with the device inactive and the server burns its tokens. Rotates the
    /// vault DEK + master password by default: the device keeps what it saw
    /// but can't read anything sealed after revocation.
    Revoke {
        device: String,
        /// Skip key rotation (tidy an old offline device, etc.) — the
        /// revoked device could still decrypt any ciphertext it obtains.
        #[arg(long)]
        keep_keys: bool,
    },
}

fn vault_dir(cli: &Cli) -> PathBuf {
    if let Some(v) = &cli.vault {
        return v.clone();
    }
    if let Ok(v) = std::env::var("MPM_VAULT") {
        return PathBuf::from(v);
    }
    dirs_home().join(".mypassman").join("vault")
}

fn dirs_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn field_map() -> BTreeMap<&'static str, (u8, bool)> {
    // name -> (tag, is_secret)
    let mut m = BTreeMap::new();
    for (n, t, s) in [
        ("username", tag::USERNAME, false),
        ("password", tag::PASSWORD, true),
        ("url", tag::URL, false),
        ("notes", tag::NOTES, true),
        ("number", tag::CARD_NUMBER, true),
        ("exp", tag::CARD_EXP, false),
        ("cvv", tag::CARD_CVV, true),
        ("holder", tag::CARD_HOLDER, false),
        ("pin", tag::CARD_PIN, true),
        ("key", tag::KEY, true),
        ("secret", tag::KEY_SECRET, true),
        ("endpoint", tag::ENDPOINT, false),
        ("env", tag::ENV, false),
        ("expires", tag::EXPIRES, false),
        ("totp_secret", tag::TOTP_SECRET, true),
        ("issuer", tag::TOTP_ISSUER, false),
        ("digits", tag::TOTP_DIGITS, false),
        ("period", tag::TOTP_PERIOD, false),
        ("algo", tag::TOTP_ALGO, false),
        ("text", tag::TEXT, true),
        ("full_name", tag::FULL_NAME, false),
        ("address", tag::ADDRESS, false),
        ("phone", tag::PHONE, false),
        ("email", tag::EMAIL, false),
        ("private", tag::SSH_PRIVATE, true),
        ("public", tag::SSH_PUBLIC, false),
        ("tags", tag::TAGS, false),
    ] {
        m.insert(n, (t, s));
    }
    m
}

fn required_fields(kind: ItemKind) -> &'static [(&'static str, bool)] {
    // (name, secret?) — prompted if not given via -f
    match kind {
        ItemKind::Login => &[("username", false), ("password", true)],
        ItemKind::Card => &[("number", true), ("exp", false), ("cvv", true)],
        ItemKind::ApiKey => &[("key", true), ("endpoint", false)],
        ItemKind::Totp => &[("totp_secret", true), ("issuer", false)],
        ItemKind::Secret => &[("text", true)],
        ItemKind::Identity => &[("full_name", false), ("email", false)],
        ItemKind::SshKey => &[("private", true), ("public", false)],
    }
}

/// Item-field prompt — NEVER reads $MPM_PASSWORD; that var is for vault
/// unlock only. Using it here would silently store the master password as
/// an item secret.
fn prompt_secret(what: &str) -> Zeroizing<String> {
    if let Ok(p) = rpassword::prompt_password(format!("{what}: ")) {
        return Zeroizing::new(p);
    }
    eprint!("{what}: ");
    std::io::Write::flush(&mut std::io::stderr()).ok();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).expect("read secret");
    Zeroizing::new(s.trim_end().to_string())
}

/// Vault-unlock secret: TTY prompt → $MPM_PASSWORD (scripting) → stdin.
/// The env var is consumed (removed) so it can't leak into item fields or
/// child processes spawned later in this process's lifetime.
pub(crate) fn read_password(prompt: &str) -> Zeroizing<String> {
    if let Ok(p) = std::env::var("MPM_PASSWORD") {
        std::env::remove_var("MPM_PASSWORD");
        return Zeroizing::new(p);
    }
    if let Ok(p) = rpassword::prompt_password(prompt) {
        return Zeroizing::new(p);
    }
    eprint!("{prompt}");
    std::io::Write::flush(&mut std::io::stderr()).ok();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).expect("read password");
    Zeroizing::new(s.trim_end().to_string())
}

fn read_line(prompt: &str) -> String {
    eprint!("{prompt}: ");
    let mut s = String::new();
    std::io::Write::flush(&mut std::io::stderr()).ok();
    std::io::stdin().read_line(&mut s).expect("read line");
    s.trim().to_string()
}

/// Open vault: manifest → password (or recovery code) → slot → replay logs
/// → checkpoint check. A `--recovery` unlock on a machine with no device key
/// (disaster restore) enrolls a fresh device signed by the owner key —
/// that's the point of the recovery kit surviving device loss.
fn unlock(dir: &Path, recovery_mode: bool) -> Result<Vault, String> {
    let mut manifest = mpm_store::load_manifest(dir).map_err(|e| e.to_string())?;
    manifest
        .kdf
        .check_bounds(DEVICE_KDF_CAP_KIB)
        .map_err(|e| e.to_string())?;

    let mut bundle = None;

    // Biometric slot first (macOS): a Touch ID-gated KEK in the Keychain
    // unwraps the bundle without any password prompt. Skipped when
    // --recovery, $MPM_PASSWORD (scripting), or $MPM_NO_BIO is set.
    #[cfg(target_os = "macos")]
    {
        if !recovery_mode
            && std::env::var_os("MPM_PASSWORD").is_none()
            && std::env::var_os("MPM_NO_BIO").is_none()
            && manifest
                .wrap_slots
                .iter()
                .any(|s| s.slot_type == SLOT_BIOMETRIC)
        {
            if let Some(kek) = bio::load(&manifest.vault_id) {
                for slot in &manifest.wrap_slots {
                    if slot.slot_type != SLOT_BIOMETRIC {
                        continue;
                    }
                    if let Ok(b) = KeyBundle::unwrap(
                        &kek,
                        &mpm_core::aad::wrap_slot(
                            &manifest.vault_id,
                            manifest.key_epoch,
                            SLOT_BIOMETRIC,
                        ),
                        &slot.blob,
                        manifest.key_epoch,
                    ) {
                        bundle = Some(b);
                        break;
                    }
                }
                if bundle.is_none() {
                    eprintln!("warning: biometric key didn't unwrap — password fallback");
                }
            }
        }
    }

    if bundle.is_none() {
        let (slot_type, secret) = if recovery_mode {
            let code = read_password("recovery code: ");
            let raw =
                recovery::parse_code(&code).map_err(|_| "malformed recovery code".to_string())?;
            (SLOT_RECOVERY, Zeroizing::new(raw.to_vec()))
        } else {
            let pw = read_password("master password: ");
            (SLOT_PASSWORD, Zeroizing::new(pw.as_bytes().to_vec()))
        };

        for slot in &manifest.wrap_slots {
            if slot.slot_type != slot_type {
                continue;
            }
            let Some((params, salt)) = &slot.kdf else {
                continue;
            };
            // one malformed/hostile slot must not brick the whole vault
            if params.check_bounds(DEVICE_KDF_CAP_KIB).is_err() {
                eprintln!("warning: skipping slot with out-of-bounds KDF params");
                continue;
            }
            let kek = zeroize::Zeroizing::new(
                kdf::derive_kek(&secret, salt, params).map_err(|e| e.to_string())?,
            );
            if let Ok(b) = KeyBundle::unwrap(
                &kek,
                &mpm_core::aad::wrap_slot(&manifest.vault_id, manifest.key_epoch, slot_type),
                &slot.blob,
                manifest.key_epoch,
            ) {
                bundle = Some(b);
                break;
            }
        }
    }
    let bundle = bundle.ok_or("unlock failed")?;

    let device = match mpm_store::load_device_key(&manifest.vault_id) {
        Ok(d) => d,
        Err(mpm_store::StoreError::NoDeviceKey) if recovery_mode => {
            eprintln!("no device key here — enrolling a fresh device via recovery kit");
            let dev = DeviceKey::generate();
            manifest.devices.push(mpm_core::DeviceEntry {
                id: dev.id,
                vk: dev.verifying_key(),
                name: "recovery device".into(),
                active: true,
                enrolled_at: mpm_core::vault::now_hlc(),
                revoked_seq: None,
                extra: Vec::new(),
            });
            manifest.snapshot_epoch += 1;
            let owner_sk = bundle.owner_signing_key();
            let bytes = manifest.to_file(&owner_sk);
            mpm_store::write_manifest(dir, &bytes).map_err(|e| e.to_string())?;
            mpm_store::save_device_key(&manifest.vault_id, &dev).map_err(|e| e.to_string())?;
            dev
        }
        Err(e) => return Err(e.to_string()),
    };

    let mut vault = Vault::new(manifest, bundle, device).map_err(|e| e.to_string())?;

    let lr = mpm_store::read_ops(dir, vault.device_id()).map_err(|e| e.to_string())?;
    for op in &lr.ops {
        vault.apply_own_op(op).map_err(|e| e.to_string())?;
    }
    if lr.torn_tail {
        eprintln!("warning: discarded torn tail of your op log (interrupted write)");
    }
    for dev_id in mpm_store::list_device_logs(dir).map_err(|e| e.to_string())? {
        if &dev_id == vault.device_id() {
            continue;
        }
        let lr = mpm_store::read_ops(dir, &dev_id).map_err(|e| e.to_string())?;
        if lr.torn_tail {
            eprintln!(
                "warning: torn tail on foreign log {}",
                mpm_store::hex(&dev_id)
            );
        }
        // Quarantine, don't wedge: keep the verified prefix (for a revoked
        // device, everything up to its revocation horizon) and warn on the
        // rest. A compromised device pushing signed garbage must not block
        // unlock — or the owner's ability to run `pair revoke`.
        let r = vault.verify_foreign_prefix(&dev_id, &lr.ops, 1, [0u8; HASH_LEN]);
        if let Some((seq, e)) = &r.failed_at {
            let why: String = match e {
                CoreError::NotEnrolled => "unknown or fully revoked device".into(),
                CoreError::RevokedWrite(_) => "ops written after revocation horizon".into(),
                _ => "verification failed — log may be tampered".into(),
            };
            eprintln!(
                "warning: quarantined log of device {} at seq {} ({})",
                mpm_store::hex(&dev_id),
                seq,
                why
            );
        }
        vault.apply_foreign(r.pts);
    }

    check_checkpoint(&vault)?;
    Ok(vault)
}

/// Compare the replayed log tip with our last verified checkpoint
/// (device-signed, stored outside the synced dir). A shorter or diverged
/// log means rollback; a longer one means the checkpoint is just stale.
fn check_checkpoint(vault: &Vault) -> Result<(), String> {
    let (seq, head) = vault.head();
    match mpm_store::load_checkpoint(&vault.manifest.vault_id, vault.device())
        .map_err(|e| e.to_string())?
    {
        Some((cseq, chead)) => {
            if cseq > seq || (cseq == seq && chead != head) {
                return Err(
                    "op log is behind/diverged from last verified state — possible rollback attack"
                        .into(),
                );
            }
            if chead != head {
                save_checkpoint(vault) // stale: log grew without us
            } else {
                Ok(())
            }
        }
        None => save_checkpoint(vault), // first unlock with this feature
    }
}

fn save_checkpoint(vault: &Vault) -> Result<(), String> {
    let (seq, head) = vault.head();
    mpm_store::save_checkpoint(&vault.manifest.vault_id, vault.device(), seq, &head)
        .map_err(|e| e.to_string())
}

fn cmd_init(dir: &Path) -> Result<(), String> {
    mpm_store::init_dir(dir).map_err(|e| e.to_string())?;
    // $MPM_PASSWORD satisfies both prompts (scripting); otherwise ask twice.
    let env_pw = std::env::var("MPM_PASSWORD").ok().map(Zeroizing::new);
    if env_pw.is_some() {
        std::env::remove_var("MPM_PASSWORD");
    }
    let pw = env_pw
        .clone()
        .unwrap_or_else(|| read_password("new master password: "));
    let pw2 = env_pw.unwrap_or_else(|| read_password("confirm: "));
    if pw.as_str() != pw2.as_str() {
        return Err("passwords don't match".into());
    }
    if pw.is_empty() {
        return Err("empty password".into());
    }

    let params = KdfParams::default();
    let mut salt = [0u8; 32];
    rand_core_fill(&mut salt);
    let kek = kdf::derive_kek(pw.as_bytes(), &salt, &params).map_err(|e| e.to_string())?;

    let bundle = KeyBundle::generate();
    let device = DeviceKey::generate();

    let mut manifest = Manifest::new(params, salt, bundle.owner_verifying_key());
    manifest.wrap_slots.push(WrapSlot {
        slot_type: SLOT_PASSWORD,
        kdf: Some((params, salt)),
        blob: bundle
            .wrap(
                &kek,
                &mpm_core::aad::wrap_slot(&manifest.vault_id, manifest.key_epoch, SLOT_PASSWORD),
            )
            .map_err(|e| e.to_string())?,
        extra: Vec::new(),
    });
    manifest.devices.push(mpm_core::DeviceEntry {
        id: device.id,
        vk: device.verifying_key(),
        name: "this device".into(),
        active: true,
        enrolled_at: mpm_core::vault::now_hlc(),
        revoked_seq: None,
        extra: Vec::new(),
    });

    // recovery slot: independent KEK from a printed-once code
    let raw_code = recovery::generate_code();
    let mut rsalt = [0u8; 32];
    rand_core_fill(&mut rsalt);
    let rkek = kdf::derive_kek(&raw_code, &rsalt, &params).map_err(|e| e.to_string())?;
    manifest.wrap_slots.push(WrapSlot {
        slot_type: SLOT_RECOVERY,
        kdf: Some((params, rsalt)),
        blob: bundle
            .wrap(
                &rkek,
                &mpm_core::aad::wrap_slot(&manifest.vault_id, manifest.key_epoch, SLOT_RECOVERY),
            )
            .map_err(|e| e.to_string())?,
        extra: Vec::new(),
    });

    let owner_sk = bundle.owner_signing_key();
    let bytes = manifest.to_file(&owner_sk);
    mpm_store::write_manifest(dir, &bytes).map_err(|e| e.to_string())?;
    mpm_store::save_device_key(&manifest.vault_id, &device).map_err(|e| e.to_string())?;

    eprintln!("vault created: {}", dir.display());
    eprintln!("vault_id: {}", mpm_store::hex(&manifest.vault_id));
    eprintln!("device:   {}", mpm_store::hex(&device.id));
    eprintln!();
    eprintln!("=== RECOVERY KIT — shown ONCE. Write it down, store it offline. ===");
    eprintln!("  code:      {}", recovery::format_code(&raw_code));
    eprintln!("  key_epoch: {}", manifest.key_epoch);
    eprintln!("  vault_id:  {}", mpm_store::hex(&manifest.vault_id));
    eprintln!("Lose your password AND this code = lose the vault.");
    Ok(())
}

fn cmd_add(
    dir: &Path,
    rec: bool,
    kind: &str,
    name: &str,
    cli_fields: &[String],
) -> Result<(), String> {
    let kind = ItemKind::from_name(kind).map_err(|_| format!("unknown kind '{kind}'"))?;
    if name.is_empty() || name.chars().any(|c| c.is_control()) {
        return Err("bad name (empty or contains control chars)".into());
    }
    let fmap = field_map();

    let mut given = BTreeMap::new();
    for f in cli_fields {
        let Some((k, v)) = f.split_once('=') else {
            return Err(format!("bad -f '{f}' (want name=value)"));
        };
        let Some((t, _)) = fmap.get(k) else {
            return Err(format!("unknown field '{k}'"));
        };
        given.insert(k.to_string(), (*t, v.to_string()));
    }

    // daemon path: merge or create without a fresh unlock
    match daemon::item(dir, name)? {
        daemon::DaemonItem::Found(mut item, Some(k), rec_name, rid0) => {
            if k != kind {
                return Err(format!(
                    "'{name}' exists as {} — rm it first to change kind",
                    k.name()
                ));
            }
            for (t, v) in given.values() {
                item.set(*t, v.clone().into_bytes());
            }
            item.set(tag::NAME, rec_name.clone().into_bytes()); // NAME is outer-layer
            for (fname, secret) in required_fields(kind) {
                let t = fmap[*fname].0;
                if *secret && item.get(t).is_none() {
                    item.set(t, prompt_secret(fname).as_bytes().to_vec());
                }
            }
            finalize_totp(&mut item)?;
            // resolved name + rid — never the raw lookup string, and the
            // update is addressed by id so it can't create a duplicate
            let Some((rid, _)) = daemon::try_put(dir, kind, &rec_name, Some(&rid0), &item)? else {
                return Err("daemon vanished mid-add".into());
            };
            eprintln!("updated '{rec_name}' ({})", mpm_store::hex(&rid));
            return Ok(());
        }
        daemon::DaemonItem::Found(_, None, _, _) => {
            return Err(format!("'{name}' exists with unknown kind"));
        }
        daemon::DaemonItem::Missing => {
            let mut item = Item::default();
            item.set(tag::NAME, name.as_bytes().to_vec());
            for (fname, secret) in required_fields(kind) {
                if given.contains_key(*fname) {
                    continue;
                }
                let t = fmap[fname].0;
                if *secret {
                    let v = prompt_secret(fname);
                    if !v.is_empty() {
                        item.set(t, v.as_bytes().to_vec());
                    }
                } else {
                    let v = read_line(fname);
                    if !v.is_empty() {
                        item.set(t, v.into_bytes());
                    }
                }
            }
            for (t, v) in given.into_values() {
                item.set(t, v.into_bytes());
            }
            finalize_totp(&mut item)?;
            let Some((rid, _)) = daemon::try_put(dir, kind, name, None, &item)? else {
                return Err("daemon vanished mid-add".into());
            };
            eprintln!(
                "added {} '{}' ({})",
                kind.name(),
                name,
                mpm_store::hex(&rid)
            );
            return Ok(());
        }
        daemon::DaemonItem::Offline => {}
    }

    // serialize the whole read-modify-write: two concurrent `add`s would
    // otherwise both mint seq N and corrupt the log
    let _lock = mpm_store::lock_vault(dir).map_err(|e| e.to_string())?;
    let mut vault = unlock(dir, rec)?;

    // exact-name match → update that record in place rather than creating
    // a same-name duplicate (which `find` could never disambiguate)
    let existing = vault
        .records()
        .find(|r| r.name == name)
        .map(|r| (r.record_id, r.kind));

    if let Some((rid, Some(old_kind))) = existing {
        if old_kind != kind {
            return Err(format!(
                "'{name}' exists as a {old_kind:?} — rm it first to change kind"
            ));
        }
        // merge: provided fields override; secrets absent get prompted
        let mut item = vault.item(&rid).map_err(|e| e.to_string())?;
        for (t, v) in given.values() {
            item.set(*t, v.clone().into_bytes());
        }
        for (fname, secret) in required_fields(kind) {
            let t = fmap[*fname].0;
            if *secret && item.get(t).is_none() {
                item.set(t, prompt_secret(fname).as_bytes().to_vec());
            }
        }
        item.set(tag::NAME, name.as_bytes().to_vec());
        finalize_totp(&mut item)?;
        let op = vault
            .make_update(&rid, kind, item)
            .map_err(|e| e.to_string())?;
        mpm_store::append_op(dir, vault.device_id(), &op).map_err(|e| e.to_string())?;
        vault.commit(&op).map_err(|e| e.to_string())?;
        save_checkpoint(&vault)?;
        eprintln!("updated '{}' ({})", name, mpm_store::hex(&rid));
        return Ok(());
    }

    let mut item = Item::default();
    item.set(tag::NAME, name.as_bytes().to_vec());

    // prompt for missing required fields — secret values go straight into
    // the Item (ZeroizeOnDrop), never through the plain-String `given` map
    for (fname, secret) in required_fields(kind) {
        if given.contains_key(*fname) {
            continue;
        }
        let t = fmap[fname].0;
        if *secret {
            let v = prompt_secret(fname);
            if !v.is_empty() {
                item.set(t, v.as_bytes().to_vec());
            }
        } else {
            let v = read_line(fname);
            if !v.is_empty() {
                item.set(t, v.into_bytes());
            }
        }
    }

    for (t, v) in given.into_values() {
        item.set(t, v.into_bytes());
    }
    finalize_totp(&mut item)?;

    let (op, rid) = vault.make_upsert(kind, item).map_err(|e| e.to_string())?;
    mpm_store::append_op(dir, vault.device_id(), &op).map_err(|e| e.to_string())?;
    vault.commit(&op).map_err(|e| e.to_string())?;
    save_checkpoint(&vault)?;
    eprintln!(
        "added {} '{}' ({})",
        kind.name(),
        name,
        mpm_store::hex(&rid)
    );
    Ok(())
}

/// Normalize any item's TOTP_SECRET field: `otpauth://` URIs expand into
/// issuer/digits/period/algo fields; bare base32 is validated and stored
/// canonical (uppercase, no padding/spaces — re-pastable into other apps).
/// Applies to ANY kind — a login can carry its own 2FA secret.
fn finalize_totp(item: &mut mpm_core::Item) -> Result<(), String> {
    let Some(raw) = item.get_str(tag::TOTP_SECRET).map(|s| s.to_string()) else {
        return Ok(());
    };
    if raw.starts_with("otpauth://") {
        let oa = mpm_core::totp::parse_otpauth(&raw).map_err(|e| e.to_string())?;
        item.set(tag::TOTP_SECRET, b32_encode(&oa.secret).into_bytes());
        if !oa.issuer.is_empty() && item.get(tag::TOTP_ISSUER).is_none() {
            item.set(tag::TOTP_ISSUER, oa.issuer.into_bytes());
        }
        item.set(tag::TOTP_DIGITS, oa.digits.to_string().into_bytes());
        item.set(tag::TOTP_PERIOD, oa.period.to_string().into_bytes());
        item.set(
            tag::TOTP_ALGO,
            format!("{:?}", oa.algo).to_uppercase().into_bytes(),
        );
    } else {
        let decoded = mpm_core::totp::base32_decode(&raw).map_err(|e| e.to_string())?;
        if decoded.is_empty() {
            return Err("empty totp secret".into());
        }
        item.set(tag::TOTP_SECRET, b32_encode(&decoded).into_bytes());
    }
    Ok(())
}

/// RFC 4648 base32, uppercase, no padding — canonical storage form.
fn b32_encode(b: &[u8]) -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity((b.len() * 8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in b {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// field tag → is-secret, via field_map. Unknown tags are secret —
/// a newer build's sensitive field must never leak through an older
/// reader's metadata path.
fn tag_secret(t: u8) -> bool {
    field_map()
        .values()
        .find(|(ft, _)| *ft == t)
        .map(|(_, s)| *s)
        .unwrap_or(true)
}

/// (all field tags present, non-secret tag→first-value) — shared by the
/// daemon LIST op and `list --json`. Tag→name mapping stays client-side.
/// Meta values are truncated: a pathological vault must not blow the
/// 1 MiB wire budget. Output is tag-sorted — canonical inner TLV order.
fn row_meta_tags(vault: &mpm_core::Vault, rid: &[u8; 16]) -> (Vec<u8>, Vec<(u8, Vec<u8>)>) {
    const META_VALUE_CAP: usize = 2048;
    let Ok(item) = vault.item(rid) else {
        return (vec![], vec![]);
    };
    let mut all = Vec::new();
    let mut ns = Vec::new();
    for (t, vals) in &item.fields {
        all.push(*t);
        if !tag_secret(*t) {
            if let Some(v) = vals.first() {
                // byte-cap, but never split a UTF-8 codepoint — a severed
                // multibyte tail becomes U+FFFD under from_utf8_lossy and a
                // client could act on a corrupted URL
                let mut n = v.len().min(META_VALUE_CAP);
                while n > 0 && n < v.len() && (v[n] & 0xC0) == 0x80 {
                    n -= 1;
                }
                ns.push((*t, v[..n].to_vec()));
            }
        }
    }
    // totp items that didn't set an explicit period still roll every 30s —
    // surface the default so clients can render a countdown
    if all.contains(&tag::TOTP_SECRET) && !all.contains(&tag::TOTP_PERIOD) {
        ns.push((tag::TOTP_PERIOD, b"30".to_vec()));
    }
    ns.sort_by_key(|(t, _)| *t);
    (all, ns)
}

/// tag byte → field name, from field_map's inverse
fn tag_name(t: u8) -> String {
    field_map()
        .iter()
        .find(|(_, (ft, _))| *ft == t)
        .map(|(n, _)| n.to_string())
        .unwrap_or_else(|| format!("0x{t:02x}"))
}

fn cmd_list(dir: &Path, rec: bool, json: bool) -> Result<(), String> {
    let mut rows: Vec<daemon::ListRow> = if let Some(rows) = daemon::try_list(dir)? {
        rows
    } else {
        let vault = unlock(dir, rec)?;
        vault
            .records()
            .map(|r| {
                let (tags, ns) = row_meta_tags(&vault, &r.record_id);
                daemon::ListRow {
                    kind: r.kind,
                    name: r.name.clone(),
                    rid: mpm_store::hex(&r.record_id),
                    fields: tags.iter().map(|t| tag_name(*t)).collect(),
                    meta: ns
                        .iter()
                        .map(|(t, v)| (tag_name(*t), String::from_utf8_lossy(v).into_owned()))
                        .collect(),
                }
            })
            .collect()
    };
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    if json {
        // JSON escaping preserves control chars; disp() would corrupt them.
        // fields = every field name present (secret presence is metadata,
        // not a secret); meta = non-secret values only.
        print!("[");
        for (i, r) in rows.iter().enumerate() {
            if i > 0 {
                print!(",");
            }
            let fields: Vec<String> = r
                .fields
                .iter()
                .map(|f| format!("\"{}\"", json_esc(f)))
                .collect();
            let meta: Vec<String> = r
                .meta
                .iter()
                .map(|(k, v)| format!("\"{}\":\"{}\"", json_esc(k), json_esc(v)))
                .collect();
            print!(
                "{{\"kind\":\"{}\",\"name\":\"{}\",\"id\":\"{}\",\"fields\":[{}],\"meta\":{{{}}}}}",
                r.kind.map(|k| k.name()).unwrap_or(""),
                json_esc(&r.name),
                r.rid,
                fields.join(","),
                meta.join(",")
            );
        }
        println!("]");
        return Ok(());
    }
    println!("{:<10} {:<40} ID", "KIND", "NAME");
    for r in rows {
        println!(
            "{:<10} {:<40} {}",
            r.kind.map(|k| k.name()).unwrap_or("-"),
            disp(&r.name),
            r.rid
        );
    }
    Ok(())
}

fn json_esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

/// A torn tail means bytes past the verified prefix never replayed —
/// appending on top would silently orphan the new op at next unlock.
/// Refuse mutations; `backup` + `restore` into a fresh dir rebuilds clean.
fn refuse_if_torn(dir: &Path, vault: &mpm_core::Vault) -> Result<(), String> {
    let lr = mpm_store::read_ops(dir, vault.device_id()).map_err(|e| e.to_string())?;
    if lr.torn_tail {
        return Err(
            "op log has a torn tail — refusing to write. `backup` then `restore`              into a fresh --vault dir rebuilds a clean log"
                .into(),
        );
    }
    Ok(())
}

/// Terminal-safe name for printing — a hostile import could embed escape
/// sequences in a name; we only ever print it sanitized.
fn disp(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn find_one(vault: &mpm_core::Vault, name: &str) -> Result<[u8; 16], String> {
    match vault.find(name) {
        mpm_core::FindResult::One(id) => Ok(id),
        mpm_core::FindResult::None => Err(format!("'{name}': not found")),
        mpm_core::FindResult::Tombstoned => Err(format!("'{name}': deleted (tombstoned)")),
        mpm_core::FindResult::Ambiguous(n) => Err(format!(
            "'{name}': ambiguous — {n} records match; use the record id"
        )),
    }
}

/// How a retrieved secret leaves the process.
enum Out {
    Print,
    Copy(String),
    /// concealed clipboard write + synthetic ⌘V (macOS autofill)
    Paste(String),
    /// synthetic per-char keystrokes, Tab between fields — pasteboard
    /// never touched (macOS)
    Type(Vec<String>),
}

fn out_fields(out: &Out) -> Vec<&str> {
    match out {
        Out::Copy(f) | Out::Paste(f) => vec![f.as_str()],
        Out::Type(fs) => fs.iter().map(|s| s.as_str()).collect(),
        Out::Print => vec![],
    }
}

/// Event-post permission check — must pass BEFORE any clipboard write so a
/// denied `--paste` never publishes the secret at all.
fn autofill_preflight() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    return autofill::preflight();
    #[cfg(not(target_os = "macos"))]
    Err("paste/type autofill is macOS-only so far".into())
}

/// ⌘V after a concealed clipboard write — macOS only; elsewhere say so.
/// `expected` is the value the pasteboard must still hold — the JXA
/// helper compares-and-posts atomically so a swapped clipboard can never
/// emit the wrong secret.
fn paste_into_app(expected: &[u8]) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    return autofill::paste(expected);
    #[cfg(not(target_os = "macos"))]
    {
        let _ = expected;
        Err("paste autofill is macOS-only so far".into())
    }
}

fn type_into_app(parts: &[&str]) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    return autofill::type_seq(parts);
    #[cfg(not(target_os = "macos"))]
    {
        let _ = parts;
        Err("type autofill is macOS-only so far".into())
    }
}

fn pick_out(c: Option<&String>, p: Option<&String>, t: &[String]) -> Result<Out, String> {
    match (c, p, t.is_empty()) {
        (Some(f), None, true) => Ok(Out::Copy(f.clone())),
        (None, Some(f), true) => Ok(Out::Paste(f.clone())),
        (None, None, false) => Ok(Out::Type(t.to_vec())),
        (None, None, true) => Ok(Out::Print),
        _ => Err("pass only one of --copy/--paste/--type".into()),
    }
}

/// Daemon-first item fetch — daemon when live, vault unlock otherwise.
fn fetch_item(dir: &Path, rec: bool, name: &str) -> Result<mpm_core::Item, String> {
    match daemon::item(dir, name)? {
        daemon::DaemonItem::Found(item, ..) => return Ok(item),
        daemon::DaemonItem::Missing => return Err(format!("'{name}': not found")),
        daemon::DaemonItem::Offline => {}
    }
    let vault = unlock(dir, rec)?;
    let rid = find_one(&vault, name)?;
    vault.item(&rid).map_err(|e| e.to_string())
}

fn cmd_get(dir: &Path, rec: bool, name: &str, show: bool, out: &Out) -> Result<(), String> {
    render_item(&fetch_item(dir, rec, name)?, show, out)
}

/// `__dopaste <id> <field>` — the second half of a two-phase fill. The
/// caller's earlier `get --copy` already published the field; we re-fetch
/// it and refuse to post ⌘V unless the pasteboard still holds exactly
/// that — overlapping fills, janitor clears, or foreign copies can never
/// emit the wrong secret. `--otp` recomputes the code (a rolled code
/// fails the compare, correctly aborting a stale paste).
fn cmd_dopaste(
    dir: &Path,
    rec: bool,
    id: &str,
    field: Option<&String>,
    otp: bool,
) -> Result<(), String> {
    // the JXA helper compares + posts atomically; Zeroizing because this
    // buffer is a secret copy that would otherwise linger after free
    let expected: zeroize::Zeroizing<Vec<u8>> = if otp {
        // recompute — a rolled code mismatches, correctly aborting a
        // stale paste
        zeroize::Zeroizing::new(totp_code(&fetch_item(dir, rec, id)?)?.0.into_bytes())
    } else {
        let field = field.ok_or("pass a field or --otp")?;
        let fmap = field_map();
        let Some((t, _)) = fmap.get(field.as_str()) else {
            return Err(format!("unknown field '{field}'"));
        };
        zeroize::Zeroizing::new(
            fetch_item(dir, rec, id)?
                .get(*t)
                .ok_or("field absent")?
                .to_vec(),
        )
    };
    paste_into_app(&expected)?;
    eprintln!("pasted");
    Ok(())
}

fn render_item(item: &mpm_core::Item, show: bool, out: &Out) -> Result<(), String> {
    let fmap = field_map();
    let inv: BTreeMap<u8, (&str, bool)> = fmap.iter().map(|(n, (t, s))| (*t, (*n, *s))).collect();

    let fields = out_fields(out);
    if !fields.is_empty() {
        match out {
            Out::Copy(f) | Out::Paste(f) => {
                let field = f.as_str();
                let Some((t, _)) = fmap.get(field) else {
                    return Err(format!("unknown field '{field}'"));
                };
                let val = item.get(*t).ok_or("field absent")?;
                match out {
                    Out::Copy(_) => {
                        copy_to_clipboard(val)?;
                        eprintln!(
                            "copied '{field}' — concealed from clipboard managers, auto-clears in {}s",
                            clip_ttl()
                        );
                    }
                    Out::Paste(_) => {
                        copy_to_clipboard(val)?; // concealed write + janitor, then ⌘V
                        paste_into_app(val)?; // JXA verifies board==val first
                        eprintln!("pasted '{field}'");
                    }
                    _ => unreachable!(),
                }
            }
            Out::Type(fs) => {
                let mut parts = Vec::with_capacity(fs.len());
                for field in fs {
                    let Some((t, _)) = fmap.get(field.as_str()) else {
                        return Err(format!("unknown field '{field}'"));
                    };
                    let val = item.get(*t).ok_or(format!("'{field}' absent"))?;
                    parts.push(
                        std::str::from_utf8(val)
                            .map_err(|_| "field isn't UTF-8 — can't type it")?,
                    );
                }
                type_into_app(&parts)?;
                eprintln!("typed {}", fs.join(" ⇥ "));
            }
            Out::Print => unreachable!(),
        }
        return Ok(());
    }

    for (t, vals) in &item.fields {
        // unknown tags default to SECRET — a newer build's sensitive field
        // must never be printed in cleartext by an older reader
        let (fname, secret) = inv.get(t).copied().unwrap_or(("?", true));
        for v in vals {
            let text = String::from_utf8_lossy(v);
            if secret && !show {
                println!("{fname}(0x{t:02x}): ********");
            } else {
                println!("{fname}: {text}");
            }
        }
    }
    Ok(())
}

fn cmd_rm(dir: &Path, rec: bool, name: &str) -> Result<(), String> {
    if daemon::try_del(dir, name)?.is_some() {
        eprintln!("deleted '{name}' (tombstoned)");
        return Ok(());
    }
    let _lock = mpm_store::lock_vault(dir).map_err(|e| e.to_string())?;
    let mut vault = unlock(dir, rec)?;
    let rid = find_one(&vault, name)?;
    let op = vault.make_tombstone(&rid).map_err(|e| e.to_string())?;
    let (rname, kind) = vault
        .records()
        .find(|r| r.record_id == rid)
        .map(|r| (r.name.clone(), r.kind))
        .ok_or("record vanished")?;
    mpm_store::append_op(dir, vault.device_id(), &op).map_err(|e| e.to_string())?;
    vault.commit(&op).map_err(|e| e.to_string())?;
    save_checkpoint(&vault)?;
    eprintln!(
        "deleted {} '{rname}' ({}) (tombstoned)",
        kind.map(|k| k.name()).unwrap_or("item"),
        mpm_store::hex(&rid)
    );
    Ok(())
}

/// `history <name>` — per-record version list rebuilt by replaying every
/// verified op (own + foreign logs) in merge order. Field values never
/// print; rows show which field KEYS changed between versions.
fn cmd_history(dir: &Path, rec: bool, name: &str, json: bool) -> Result<(), String> {
    let vault = unlock(dir, rec)?;

    // unlock() already verified every log once; re-verifying per device
    // recovers the plaintexts history needs. verify_foreign_log covers
    // our own log too — this device is in the manifest registry.
    let mut pts: Vec<mpm_core::OpPlaintext> = Vec::new();
    for dev in mpm_store::list_device_logs(dir).map_err(|e| e.to_string())? {
        let lr = mpm_store::read_ops(dir, &dev).map_err(|e| e.to_string())?;
        // same quarantine semantics as unlock: keep the verified prefix
        // (a revoked device contributes up to its horizon), skip the rest
        let r = vault.verify_foreign_prefix(&dev, &lr.ops, 1, [0u8; HASH_LEN]);
        pts.extend(r.pts);
    }
    // the merge's total order — the same key apply_pt compares on
    pts.sort_by_key(|p| (p.hlc, p.origin_device, p.origin_seq));

    // latest name + liveness per record. Names ride on upsert ops; a
    // tombstone keeps the last name so history still finds deleted items
    // (vault.find can't — its index hides tombstoned names).
    let mut recs: BTreeMap<[u8; 16], (String, bool)> = BTreeMap::new();
    for p in &pts {
        let e = recs.entry(p.record_id).or_default();
        match p.op_type {
            mpm_core::OpType::Upsert => {
                e.0 = String::from_utf8_lossy(&p.name).into_owned();
                e.1 = false;
            }
            mpm_core::OpType::Tombstone => e.1 = true,
            mpm_core::OpType::Meta => {}
        }
    }

    // resolve like find(): exact name → record-id hex prefix → unique
    // substring — but over ALL records, tombstoned included
    let mut cands: Vec<[u8; 16]> = recs
        .iter()
        .filter(|(_, (n, _))| n.eq_ignore_ascii_case(name))
        .map(|(r, _)| *r)
        .collect();
    if !name.is_empty() && name.bytes().all(|b| b.is_ascii_hexdigit()) {
        let low = name.to_lowercase();
        for r in recs.keys() {
            if mpm_store::hex(r).starts_with(&low) && !cands.contains(r) {
                cands.push(*r);
            }
        }
    }
    if cands.is_empty() {
        let needle = name.to_lowercase();
        cands = recs
            .iter()
            .filter(|(_, (n, _))| n.to_lowercase().contains(&needle))
            .map(|(r, _)| *r)
            .collect();
    }
    let rid = match cands.len() {
        0 => return Err(format!("'{name}': not found")),
        1 => cands[0],
        n => {
            eprintln!("'{name}': ambiguous — {n} records match, pass an id prefix:");
            for r in &cands {
                let (rn, dead) = &recs[r];
                eprintln!(
                    "  {} {:<40} {}",
                    &mpm_store::hex(r)[..8],
                    disp(rn),
                    if *dead { "(deleted)" } else { "" }
                );
            }
            return Err("use a record id prefix".into());
        }
    };

    let dev_name = |d: &[u8; 16]| -> String {
        vault
            .manifest
            .device(d)
            .map(|e| disp(&e.name))
            .unwrap_or_else(|| mpm_store::hex(&d[..8]))
    };

    // decrypt each upsert in order; diff field keys vs the previous upsert
    struct Row {
        op: mpm_core::OpType,
        hlc: u64,
        dev: [u8; 16],
        changed: Vec<String>,
    }
    let mut rows: Vec<Row> = Vec::new();
    let mut prev: Option<(Item, Vec<u8>)> = None; // last upsert's (item, name)
    for p in pts.iter().filter(|p| p.record_id == rid) {
        if p.op_type != mpm_core::OpType::Upsert {
            rows.push(Row {
                op: p.op_type,
                hlc: p.hlc,
                dev: p.origin_device,
                changed: Vec::new(),
            });
            continue;
        }
        let dek = vault
            .bundle()
            .dek_at(p.key_epoch)
            .ok_or("no DEK for record epoch — vault key set is stale".to_string())?;
        let item = p
            .open_fields(dek, &vault.manifest.vault_id)
            .map_err(|e| e.to_string())?;
        let mut changed: Vec<String> = Vec::new();
        if let Some((_, pname)) = &prev {
            if pname.as_slice() != p.name.as_slice() {
                changed.push("name".into());
            }
        }
        let mut tags: std::collections::BTreeSet<u8> = item.fields.keys().copied().collect();
        if let Some((pi, _)) = &prev {
            tags.extend(pi.fields.keys().copied());
        }
        for t in tags {
            let pv = prev.as_ref().and_then(|(pi, _)| pi.fields.get(&t));
            if pv != item.fields.get(&t) {
                changed.push(tag_name(t));
            }
        }
        rows.push(Row {
            op: p.op_type,
            hlc: p.hlc,
            dev: p.origin_device,
            changed,
        });
        prev = Some((item, p.name.clone()));
    }

    let op_name = |op: mpm_core::OpType| match op {
        mpm_core::OpType::Upsert => "upsert",
        mpm_core::OpType::Tombstone => "tombstone",
        mpm_core::OpType::Meta => "meta",
    };
    if json {
        let mut objs = Vec::new();
        for (i, r) in rows.iter().enumerate().rev() {
            let ch: Vec<String> = r
                .changed
                .iter()
                .map(|c| format!("\"{}\"", json_esc(c)))
                .collect();
            objs.push(format!(
                "{{\"v\":{},\"ts\":\"{}\",\"hlc\":{},\"device\":\"{}\",\"device_id\":\"{}\",\"op\":\"{}\",\"changed\":[{}]}}",
                i + 1,
                fmt_hlc(r.hlc),
                r.hlc,
                json_esc(&dev_name(&r.dev)),
                mpm_store::hex(&r.dev),
                op_name(r.op),
                ch.join(",")
            ));
        }
        println!("[{}]", objs.join(","));
        return Ok(());
    }
    let title = if recs[&rid].0.is_empty() {
        name.to_string()
    } else {
        recs[&rid].0.clone()
    };
    eprintln!(
        "{} ({}) — {} version(s), newest first",
        disp(&title),
        &mpm_store::hex(&rid)[..8],
        rows.len()
    );
    eprintln!(
        "{:<3} {:<20} {:<16} FIELDS CHANGED",
        "#", "HLC/ts", "DEVICE"
    );
    for (i, r) in rows.iter().enumerate().rev() {
        let label = match r.op {
            mpm_core::OpType::Tombstone => "(deleted)".to_string(),
            mpm_core::OpType::Meta => "(meta)".to_string(),
            mpm_core::OpType::Upsert if i == 0 => "(created)".to_string(),
            mpm_core::OpType::Upsert if r.changed.is_empty() => "(unchanged)".to_string(),
            mpm_core::OpType::Upsert => r.changed.join(", "),
        };
        eprintln!(
            "{:<3} {:<20} {:<16} {}",
            i + 1,
            fmt_hlc(r.hlc),
            dev_name(&r.dev),
            label
        );
    }
    Ok(())
}

/// hlc millis → "YYYY-MM-DD HH:MM:SSZ" (UTC; civil-from-days, no chrono dep)
fn fmt_hlc(ms: u64) -> String {
    let secs = ms / 1000;
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        tod / 3600,
        tod % 3600 / 60,
        tod % 60
    )
}

fn cmd_passwd(dir: &Path, rec: bool) -> Result<(), String> {
    let mut vault = unlock(dir, rec)?;
    let p1 = read_password("new master password: ");
    let p2 = read_password("confirm new password: ");
    if *p1 != *p2 {
        return Err("passwords don't match".into());
    }
    if p1.is_empty() {
        return Err("empty password".into());
    }
    let params = KdfParams::default();
    let mut salt = [0u8; 32];
    rand_core_fill(&mut salt);
    let kek = kdf::derive_kek(p1.as_bytes(), &salt, &params).map_err(|e| e.to_string())?;
    let blob = vault
        .bundle()
        .wrap(
            &kek,
            &mpm_core::aad::wrap_slot(
                &vault.manifest.vault_id,
                vault.manifest.key_epoch,
                SLOT_PASSWORD,
            ),
        )
        .map_err(|e| e.to_string())?;
    vault
        .manifest
        .wrap_slots
        .retain(|s| s.slot_type != SLOT_PASSWORD);
    vault.manifest.wrap_slots.push(WrapSlot {
        slot_type: SLOT_PASSWORD,
        kdf: Some((params, salt)),
        blob,
        extra: Vec::new(),
    });
    vault.manifest.snapshot_epoch += 1;
    let bytes = vault.manifest.to_file(&vault.bundle().owner_signing_key());
    mpm_store::write_manifest(dir, &bytes).map_err(|e| e.to_string())?;
    eprintln!("master password changed");
    eprintln!("note: sync propagates the new manifest; other devices unlock with the new password");
    eprintln!("note: manifest copies already out there still open with the OLD password —");
    eprintln!("      if the old password may be compromised, `pair revoke` rotates the DEK too");
    Ok(())
}

fn cmd_recovery_rotate(dir: &Path, rec: bool) -> Result<(), String> {
    let _lock = mpm_store::lock_vault(dir).map_err(|e| e.to_string())?;
    let mut vault = unlock(dir, rec)?;
    let raw_code = recovery::generate_code();
    let params = KdfParams::default();
    let mut rsalt = [0u8; 32];
    rand_core_fill(&mut rsalt);
    let rkek = kdf::derive_kek(&raw_code, &rsalt, &params).map_err(|e| e.to_string())?;

    vault
        .manifest
        .wrap_slots
        .retain(|s| s.slot_type != SLOT_RECOVERY);
    vault.manifest.wrap_slots.push(WrapSlot {
        slot_type: SLOT_RECOVERY,
        kdf: Some((params, rsalt)),
        blob: vault
            .bundle()
            .wrap(
                &rkek,
                &mpm_core::aad::wrap_slot(
                    &vault.manifest.vault_id,
                    vault.manifest.key_epoch,
                    SLOT_RECOVERY,
                ),
            )
            .map_err(|e| e.to_string())?,
        extra: Vec::new(),
    });
    vault.manifest.snapshot_epoch += 1;
    let owner_sk = vault.bundle().owner_signing_key();
    let bytes = vault.manifest.to_file(&owner_sk);
    mpm_store::write_manifest(dir, &bytes).map_err(|e| e.to_string())?;

    eprintln!("=== NEW RECOVERY KIT ===");
    eprintln!("  code:      {}", recovery::format_code(&raw_code));
    eprintln!("  key_epoch: {}", vault.manifest.key_epoch);
    eprintln!();
    eprintln!("This re-wraps the SAME vault keys under a new code. The old code no");
    eprintln!("longer unlocks THIS manifest — but anyone holding an old manifest copy");
    eprintln!("plus the old code still holds the keys. If the kit may have leaked,");
    eprintln!("rotate your master password too, and rotate exposed credentials — full");
    eprintln!("key-epoch rotation (new DEK) lands with sync (M3).");
    Ok(())
}

fn cmd_gen(
    len: Option<usize>,
    passphrase: bool,
    no_symbols: bool,
    copy: bool,
) -> Result<(), String> {
    // separate defaults: 20 chars for charset mode, 6 words for passphrase
    let len = len.unwrap_or(if passphrase { 6 } else { 20 });
    if len == 0 || len > 1024 {
        return Err("bad length".into());
    }
    let out = if passphrase {
        gen::passphrase(len.max(3))
    } else {
        gen::password(len, !no_symbols)
    };
    if copy {
        copy_to_clipboard(out.as_bytes())?;
        eprintln!(
            "copied — concealed from clipboard managers, auto-clears in {}s",
            clip_ttl()
        );
    } else {
        println!("{}", out.as_str());
    }
    Ok(())
}

/// current TOTP code + seconds-left for an item carrying totp_secret
fn totp_code(item: &mpm_core::Item) -> Result<(String, u64), String> {
    let b32 = item
        .get_str(tag::TOTP_SECRET)
        .ok_or("item has no totp_secret field")?;
    let secret = mpm_core::totp::base32_decode(b32).map_err(|e| e.to_string())?;
    let digits: u32 = item
        .get_str(tag::TOTP_DIGITS)
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);
    let period: u64 = item
        .get_str(tag::TOTP_PERIOD)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let algo = mpm_core::totp::TotpAlgo::from_name(item.get_str(tag::TOTP_ALGO).unwrap_or("SHA1"))
        .map_err(|e| e.to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Ok(mpm_core::totp::totp(&secret, now, period, digits, algo))
}

/// `otp <name>` — current TOTP code for any item carrying a totp_secret
/// (a login can hold its own 2FA; a `totp` item is the standalone form).
fn cmd_otp(dir: &Path, rec: bool, name: &str, out: &Out) -> Result<(), String> {
    let item = match daemon::item(dir, name)? {
        daemon::DaemonItem::Found(i, _, _, _) => i,
        daemon::DaemonItem::Missing => return Err(format!("'{name}': not found")),
        daemon::DaemonItem::Offline => {
            let vault = unlock(dir, rec)?;
            let rid = find_one(&vault, name)?;
            vault.item(&rid).map_err(|e| e.to_string())?
        }
    };
    let (code, left) = totp_code(&item)?;
    match out {
        Out::Copy(_) => {
            copy_to_clipboard(code.as_bytes())?;
            eprintln!("copied code — auto-clears in {}s", clip_ttl());
        }
        Out::Paste(_) => {
            copy_to_clipboard(code.as_bytes())?;
            paste_into_app(code.as_bytes())?;
            eprintln!("pasted code");
        }
        Out::Type(_) => {
            autofill_preflight()?;
            type_into_app(&[&code])?;
            eprintln!("typed code");
        }
        Out::Print => println!("{code}  (valid {left}s more)"),
    }
    Ok(())
}

/// `edit <name> -f field=val …` — update fields on an EXISTING item.
/// Unlike `add` it refuses to create: typos can't spawn stray records.
fn cmd_edit(dir: &Path, rec: bool, name: &str, cli_fields: &[String]) -> Result<(), String> {
    if cli_fields.is_empty() {
        return Err("nothing to change — pass -f field=value".into());
    }
    if let daemon::DaemonItem::Found(mut item, kind, rec_name, rid0) = daemon::item(dir, name)? {
        let fmap = field_map();
        for f in cli_fields {
            let Some((k, v)) = f.split_once('=') else {
                return Err(format!("bad -f '{f}' (want field=value)"));
            };
            let Some((t, _)) = fmap.get(k) else {
                return Err(format!("unknown field '{k}'"));
            };
            item.set(*t, v.as_bytes().to_vec());
        }
        item.set(tag::NAME, rec_name.clone().into_bytes()); // NAME is outer-layer — re-inject
        finalize_totp(&mut item)?;
        let Some(kind) = kind else {
            return Err("daemon: record kind unknown".into());
        };
        // update-by-rid: a concurrent delete can't turn this into a create
        let Some((rid, _)) = daemon::try_put(dir, kind, &rec_name, Some(&rid0), &item)? else {
            return Err("daemon vanished mid-edit".into());
        };
        eprintln!("updated '{rec_name}' ({})", mpm_store::hex(&rid));
        return Ok(());
    }
    let _lock = mpm_store::lock_vault(dir).map_err(|e| e.to_string())?;
    let mut vault = unlock(dir, rec)?;
    let rid = find_one(&vault, name)?;
    let fmap = field_map();
    let mut item = vault.item(&rid).map_err(|e| e.to_string())?;
    let rec = vault
        .records()
        .find(|r| r.record_id == rid)
        .map(|r| (r.name.clone(), r.kind))
        .ok_or("record vanished")?;
    item.set(tag::NAME, rec.0.into_bytes()); // NAME is outer-layer — re-inject
    let kind = rec.1.ok_or("record has no kind")?;
    for f in cli_fields {
        let Some((k, v)) = f.split_once('=') else {
            return Err(format!("bad -f '{f}' (want name=value)"));
        };
        let Some((t, _)) = fmap.get(k) else {
            return Err(format!("unknown field '{k}'"));
        };
        item.set(*t, v.as_bytes().to_vec());
    }
    finalize_totp(&mut item)?;
    let op = vault
        .make_update(&rid, kind, item)
        .map_err(|e| e.to_string())?;
    refuse_if_torn(dir, &vault)?;
    mpm_store::append_op(dir, vault.device_id(), &op).map_err(|e| e.to_string())?;
    vault.commit(&op).map_err(|e| e.to_string())?;
    save_checkpoint(&vault)?;
    eprintln!("updated '{}' ({})", disp(name), mpm_store::hex(&rid));
    Ok(())
}

/// `run -i item:field=ENV … -- cmd` — spawn with secrets in the child's
/// environment. Never on argv (argv is world-readable via ps). The child
/// inherits everything EXCEPT MPM_PASSWORD.
fn cmd_run(dir: &Path, rec: bool, inject: &[String], cmd: &[String]) -> Result<(), String> {
    let fmap = field_map();
    // validate every mapping before unlocking or touching the daemon
    struct Inj {
        envvar: String,
        iname: String,
        tag: u8,
    }
    let mut specs = Vec::new();
    for spec in inject {
        let Some((itempart, envvar)) = spec.split_once('=') else {
            return Err(format!("bad -i '{spec}' (want item:field=ENV_VAR)"));
        };
        // rsplit: the item name may itself contain ':' (aws:prod)
        let Some((iname, fname)) = itempart.rsplit_once(':') else {
            return Err(format!("bad -i '{spec}' (want item:field=ENV_VAR)"));
        };
        let Some((t, _)) = fmap.get(fname) else {
            return Err(format!("unknown field '{fname}'"));
        };
        let mut ch = envvar.chars();
        if envvar.is_empty()
            || !envvar
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            || ch.next().is_some_and(|c| c.is_ascii_digit())
        {
            return Err(format!("bad env var name '{envvar}'"));
        }
        specs.push(Inj {
            envvar: envvar.to_string(),
            iname: iname.to_string(),
            tag: *t,
        });
    }

    let mut c = std::process::Command::new(&cmd[0]);
    c.args(&cmd[1..]);
    // every reserved credential var — a child must not inherit an
    // unrelated passphrase just because it was in our environment
    for var in ["MPM_PASSWORD", "MPM_EXPORT_PASSWORD"] {
        c.env_remove(var);
    }

    // daemon first; a daemon that died between alive() and item() is
    // Offline → fall through to a real unlock rather than "not found".
    // Missing stays authoritative when the daemon is alive.
    let mut offline = false;
    if daemon::alive(dir) {
        for spec in &specs {
            match daemon::item(dir, &spec.iname)? {
                daemon::DaemonItem::Found(item, _, _, _) => {
                    let val = item
                        .get(spec.tag)
                        .ok_or(format!("'{}' has no such field", spec.iname))?;
                    c.env(&spec.envvar, String::from_utf8_lossy(val).into_owned());
                }
                daemon::DaemonItem::Missing => {
                    return Err(format!("'{}': not found", spec.iname));
                }
                daemon::DaemonItem::Offline => {
                    offline = true;
                    break;
                }
            }
        }
    }
    if !daemon::alive(dir) || offline {
        let vault = unlock(dir, rec)?;
        for spec in &specs {
            let rid = find_one(&vault, &spec.iname)?;
            let item = vault.item(&rid).map_err(|e| e.to_string())?;
            let val = item
                .get(spec.tag)
                .ok_or(format!("'{}' has no such field", spec.iname))?;
            c.env(&spec.envvar, String::from_utf8_lossy(val).into_owned());
        }
    }
    let st = c.status().map_err(|e| format!("spawn {}: {e}", cmd[0]))?;
    std::process::exit(st.code().unwrap_or(1));
}

fn cmd_devices(dir: &Path, rec: bool) -> Result<(), String> {
    // unlock first: the registry is only authentic once owner_vk has been
    // anchored against the unwrapped key bundle
    let vault = unlock(dir, rec)?;
    let manifest = &vault.manifest;
    println!("{:<34} {:<20} {:<8} ENROLLED", "DEVICE", "NAME", "STATUS");
    for d in &manifest.devices {
        println!(
            "{:<34} {:<20} {:<8} {}",
            mpm_store::hex(&d.id),
            d.name,
            if d.active { "active" } else { "revoked" },
            d.enrolled_at
        );
    }
    Ok(())
}

/// Seconds before the janitor clears a copied secret. `MPM_CLIP_TTL` overrides.
const CLIP_TTL_SECS: u64 = 45;

/// Credential env vars must never propagate into helper subprocesses
/// (osascript, pbcopy/pbpaste, powershell, our own janitor child…).
fn scrub_env(c: &mut std::process::Command) -> &mut std::process::Command {
    c.env_remove("MPM_PASSWORD")
        .env_remove("MPM_EXPORT_PASSWORD")
}

fn clip_ttl() -> u64 {
    std::env::var("MPM_CLIP_TTL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(CLIP_TTL_SECS)
}

/// Spawn the detached `__clipclear` janitor; its token arrives on stdin.
/// Detach matters: a plain child dies with the terminal's process group
/// (Ctrl-C/SIGHUP mid-sleep → the secret stays on the clipboard forever).
/// setsid on unix, DETACHED_PROCESS on Windows.
fn spawn_janitor() -> Result<std::process::ChildStdin, String> {
    use std::process::{Command, Stdio};
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut c = Command::new(exe);
    c.arg("__clipclear")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    scrub_env(&mut c);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            c.pre_exec(|| {
                libc::setsid();
                Ok(())
            })
        };
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        c.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    let mut child = c.spawn().map_err(|e| e.to_string())?;
    child.stdin.take().ok_or_else(|| "janitor stdin".into())
}

#[cfg(target_os = "macos")]
fn copy_to_clipboard(val: &[u8]) -> Result<(), String> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    // Janitor FIRST: if it can't spawn, we don't publish the secret at all.
    let mut jin = spawn_janitor()?;

    // NSPasteboard via JXA: writes the string AND marks the item
    // org.nspasteboard.ConcealedType + AutoGeneratedType — the convention
    // Raycast/Maccy/Paste honor by skipping the item in history.
    // Payload on stdin (never argv/env/script text); changeCount on stdout.
    // Non-UTF-8 payloads are rejected: initWithDataEncoding yields null and
    // setStringForType(null) would write nothing while exiting 0.
    const JXA: &str = r#"
ObjC.import('AppKit');
ObjC.import('stdlib'); // $.exit — not a builtin without this import
var d = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
var s = $.NSString.alloc.initWithDataEncoding(d, $.NSUTF8StringEncoding).js;
if (typeof s !== 'string' || s.length === 0) { $.exit(3); }
var pb = $.NSPasteboard.generalPasteboard;
pb.clearContents;
var it = $.NSPasteboardItem.alloc.init;
it.setStringForType(s, 'public.utf8-plain-text');
it.setDataForType($.NSData.data, 'org.nspasteboard.ConcealedType');
it.setDataForType($.NSData.data, 'org.nspasteboard.AutoGeneratedType');
pb.writeObjects($([it]));
pb.changeCount;
"#;
    let mut p = scrub_env(
        Command::new("osascript")
            .args(["-l", "JavaScript", "-e", JXA])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped()),
    )
    .spawn()
    .map_err(|e| e.to_string())?;
    p.stdin
        .take()
        .unwrap()
        .write_all(val)
        .map_err(|e| e.to_string())?;
    let mut out = String::new();
    let ok = p.wait().map_err(|e| e.to_string())?.success();
    if !ok {
        let _ = jin.write_all(b"\n"); // release janitor without a token
        return Err("clipboard write failed".into());
    }
    p.stdout.take().unwrap().read_to_string(&mut out).ok();
    let cc = out.trim();
    if !cc.bytes().all(|b| b.is_ascii_digit()) {
        return Err("no pasteboard changeCount".into());
    }
    let _ = jin.write_all(format!("cc:{cc}\n").as_bytes());
    Ok(())
}

/// Janitor body: sleep, then clear iff our write is still the latest.
/// `cc:N` → pasteboard changeCount (macOS): monotonic, so an identical
/// re-copy or any other write invalidates us; compare+clear run inside a
/// single osascript eval — tighter than read-subprocess-then-clear.
/// `hash:<hex>` → content compare via platform read (non-macOS).
fn cmd_clipclear() -> Result<(), String> {
    use std::io::Read;
    let mut token = String::new();
    std::io::stdin()
        .read_to_string(&mut token)
        .map_err(|e| e.to_string())?;
    let token = token.trim().to_string();
    if token.is_empty() {
        return Ok(());
    }
    std::thread::sleep(std::time::Duration::from_secs(clip_ttl()));
    if let Some(cc) = token.strip_prefix("cc:") {
        if !cc.bytes().all(|b| b.is_ascii_digit()) {
            return Err("bad token".into());
        }
        let script = format!(
            "ObjC.import('AppKit');var pb=$.NSPasteboard.generalPasteboard;if(pb.changeCount=={cc})pb.clearContents;"
        );
        let _ = scrub_env(std::process::Command::new("osascript").args([
            "-l",
            "JavaScript",
            "-e",
            &script,
        ]))
        .status();
    } else if let Some(hash) = token.strip_prefix("hash:") {
        if let Some(cur) = clip_read() {
            if blake3::hash(&cur).to_hex().as_str() == hash {
                clip_clear();
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn copy_to_clipboard(val: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    if !clip_clear_supported() {
        // no read/clear tooling → a copied secret would sit forever; fail
        // closed rather than publish without the janitor
        return Err("no clipboard auto-clear support on this platform".into());
    }
    // janitor spawned before the write — a failed spawn means no publish
    let mut jin = spawn_janitor()?;

    // write via whatever the platform offers, then hand the janitor the hash
    let tools: &[(&str, &[&str])] = if cfg!(target_os = "windows") {
        &[("clip", &[])]
    } else {
        &[
            ("wl-copy", &[]),
            ("xclip", &["-selection", "clipboard"]),
            ("xsel", &["--clipboard", "--input"]),
        ]
    };
    let mut wrote = false;
    for &(cmd, args) in tools {
        if let Ok(mut p) = scrub_env(Command::new(cmd).args(args).stdin(Stdio::piped())).spawn() {
            if let Some(mut s) = p.stdin.take() {
                if s.write_all(val).is_ok() {
                    drop(s);
                    let _ = p.wait();
                    wrote = true;
                    break;
                }
            }
        }
    }
    if !wrote {
        let _ = jin.write_all(b"\n"); // release janitor without a token
        return Err("no clipboard tool found (wl-copy/xclip/xsel/clip)".into());
    }

    // concealment: no standard on Linux/X11 or `clip`; KDE hint and Windows'
    // ExcludeClipboardContentFromMonitorProcessing need real API bindings —
    // noted in DESIGN.md. Janitor auto-clear still applies everywhere.
    let hash = blake3::hash(val).to_hex().to_string();
    let _ = jin.write_all(format!("hash:{hash}\n").as_bytes());
    Ok(())
}

/// Read current clipboard bytes — per platform.
#[cfg(target_os = "macos")]
fn clip_read() -> Option<Vec<u8>> {
    scrub_env(&mut std::process::Command::new("pbpaste"))
        // clipboard bytes are decoded as text by pbpaste — pin UTF-8 so a
        // non-UTF-8 locale can't mangle multibyte secrets
        .env("LANG", "en_US.UTF-8")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| o.stdout)
}

#[cfg(target_os = "linux")]
fn clip_read() -> Option<Vec<u8>> {
    for (cmd, args) in [
        ("wl-paste", ["-n"].as_slice()),
        ("xclip", ["-selection", "clipboard", "-o"].as_slice()),
        ("xsel", ["--clipboard", "--output"].as_slice()),
    ] {
        if let Ok(o) = scrub_env(std::process::Command::new(cmd).args(args)).output() {
            if o.status.success() {
                return Some(o.stdout);
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn clip_read() -> Option<Vec<u8>> {
    scrub_env(&mut std::process::Command::new("powershell"))
        .args(["-NoProfile", "-Command", "Get-Clipboard -Raw"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| o.stdout)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn clip_read() -> Option<Vec<u8>> {
    None
}

/// Clear the clipboard — per platform.
fn clip_clear() -> bool {
    #[cfg(target_os = "macos")]
    let cmds: &[(&str, &[&str])] = &[("sh", &["-c", "pbcopy < /dev/null"])];
    #[cfg(target_os = "linux")]
    let cmds: &[(&str, &[&str])] = &[
        ("wl-copy", &["-c"]),
        ("sh", &["-c", "printf '' | xclip -selection clipboard"]),
        ("sh", &["-c", "xsel --clipboard --clear"]),
    ];
    #[cfg(target_os = "windows")]
    let cmds: &[(&str, &[&str])] = &[(
        "powershell",
        &["-NoProfile", "-Command", "Set-Clipboard -Value ''"],
    )];
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let cmds: &[(&str, &[&str])] = &[];

    for &(cmd, args) in cmds {
        if let Ok(st) = scrub_env(std::process::Command::new(cmd).args(args)).status() {
            if st.success() {
                return true;
            }
        }
    }
    false
}

/// Is `cmd` on PATH? Pure filesystem check — probing tools by spawning them
/// risks side effects (a bare `wl-copy` reads stdin → clobbers clipboard).
#[cfg(not(target_os = "macos"))]
fn on_path(cmd: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path)
        .any(|d| d.join(cmd).is_file() || d.join(format!("{cmd}.exe")).is_file())
}

#[cfg(not(target_os = "macos"))]
fn clip_clear_supported() -> bool {
    if cfg!(target_os = "windows") {
        on_path("powershell") || on_path("pwsh")
    } else {
        on_path("wl-copy") || on_path("xclip") || on_path("xsel")
    }
}

pub(crate) fn rand_core_fill(b: &mut [u8]) {
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, b);
}

// ── export / import ─────────────────────────────────────────────────

/// Export passphrase: $MPM_EXPORT_PASSWORD (consumed) or a TTY/stdin
/// prompt. Distinct from the vault password on purpose — an export blob
/// must not inherit the vault's slot semantics.
fn export_passphrase(confirm: bool) -> Result<Zeroizing<String>, String> {
    let p = if let Ok(p) = std::env::var("MPM_EXPORT_PASSWORD") {
        std::env::remove_var("MPM_EXPORT_PASSWORD");
        Zeroizing::new(p)
    } else {
        let p = read_password("export passphrase: ");
        if confirm {
            let p2 = read_password("confirm passphrase: ");
            if p.as_str() != p2.as_str() {
                return Err("passphrases don't match".into());
            }
        }
        p
    };
    // the whole vault sits under this one passphrase — floor it
    if p.len() < 8 {
        return Err("export passphrase must be ≥8 chars".into());
    }
    Ok(p)
}

/// Create `path` 0600, refusing to overwrite. Export/backup artifacts are
/// ciphertext, but permissions stay tight regardless.
fn write_private_file(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    std::io::Write::write_all(&mut f, data).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    Ok(())
}

fn cmd_export(dir: &Path, rec: bool, path: &Path) -> Result<(), String> {
    let vault = unlock(dir, rec)?; // consumes $MPM_PASSWORD first
    let pw = export_passphrase(true)?;
    let mut recs = Vec::new();
    let mut skipped = 0usize;
    for r in vault.records() {
        let Some(kind) = r.kind else {
            skipped += 1;
            continue;
        };
        let item = vault.item(&r.record_id).map_err(|e| e.to_string())?;
        recs.push(mpm_core::export::ExportRecord {
            kind,
            name: r.name.clone(),
            fields: zeroize::Zeroizing::new(item.encode()),
        });
    }
    let blob = mpm_core::export::seal_export(&recs, pw.as_bytes()).map_err(|e| e.to_string())?;
    write_private_file(path, &blob)?;
    eprint!("exported {} records → {}", recs.len(), path.display());
    if skipped > 0 {
        eprint!(" ({skipped} skipped: unknown kind)");
    }
    eprintln!();
    Ok(())
}

/// Parse an import file into items, from any of the three formats.
/// otpauth is auto-detected too — a plaintext URI list needs no flag.
fn load_import_items(
    path: &Path,
    csv: bool,
    otpauth: bool,
) -> Result<Vec<(ItemKind, String, mpm_core::Item)>, String> {
    if csv && otpauth {
        return Err("--csv and --otpauth are mutually exclusive".into());
    }
    const MAX_IMPORT: u64 = 64 << 20; // bound hostile files before alloc
    let len = std::fs::metadata(path)
        .map_err(|e| format!("read {}: {e}", path.display()))?
        .len();
    if len > MAX_IMPORT {
        return Err(format!("{}: >64 MiB — refusing to import", path.display()));
    }
    let raw = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if otpauth || (!csv && raw.trim_ascii_start().starts_with(b"otpauth://")) {
        return otpauth_to_items(&raw);
    }
    if csv {
        return csv_to_items(&raw);
    }
    let pw = export_passphrase(false)?;
    let recs = mpm_core::export::open_export(&raw, pw.as_bytes()).map_err(|e| e.to_string())?;
    recs.iter()
        .map(|r| {
            Item::decode(&r.fields)
                .map(|it| (r.kind, r.name.clone(), it))
                .map_err(|e| e.to_string())
        })
        .collect()
}

fn cmd_import(
    dir: &Path,
    rec: bool,
    path: &Path,
    csv: bool,
    otpauth: bool,
    dry_run: bool,
) -> Result<(), String> {
    if dry_run {
        // parse + canonicalize + validate, never touch the vault or keys —
        // a dry-run must fail on everything the real import would fail on
        let mut items = load_import_items(path, csv, otpauth)?;
        for (_, _, item) in &mut items {
            finalize_totp(item)?;
        }
        if items.len() > 100_000 {
            return Err(format!("{} items — absurd, refusing", items.len()));
        }
        println!("would import {} items:", items.len());
        let mut kinds: std::collections::BTreeMap<&str, usize> = Default::default();
        for (k, _, _) in &items {
            *kinds.entry(k.name()).or_default() += 1;
        }
        for (k, n) in kinds {
            println!("  {k}: {n}");
        }
        return Ok(());
    }
    let _lock = mpm_store::lock_vault(dir).map_err(|e| e.to_string())?;
    let mut vault = unlock(dir, rec)?;
    let mut items = load_import_items(path, csv, otpauth)?;

    // validate/canonicalize everything up front — finalize_totp inside the
    // append loop would abort a HALF-applied import with no rollback
    for (_, _, item) in &mut items {
        finalize_totp(item)?;
    }
    if items.len() > 100_000 {
        return Err(format!("{} items — absurd, refusing", items.len()));
    }
    refuse_if_torn(dir, &vault)?;
    let mut created = 0usize;
    let mut updated = 0usize;
    // names minted in THIS batch — a second "Google" row must become
    // "Google-2", not silently replace the first
    let mut batch_names: std::collections::HashSet<String> = Default::default();
    for (kind, name, mut item) in items {
        // resolve the final name in ONE loop: batch dup → name-2/-3…;
        // name taken in the vault by another kind → -imported suffixes;
        // the FINAL minted name is what must land in batch_names — the
        // old code recorded the raw name and let a later row overwrite
        // the record the suffix had just created
        let mut use_name = name.clone();
        let mut n = 2usize;
        loop {
            if batch_names.contains(&use_name) {
                use_name = format!("{name}-{n}");
                n += 1;
                continue;
            }
            let existing = vault
                .records()
                .find(|r| r.name == use_name)
                .map(|r| (r.record_id, r.kind));
            match existing {
                Some((rid, Some(k))) if k == kind => {
                    // NAME must be use_name, not the original — else the
                    // update renames the suffixed record back onto the
                    // conflicting name
                    item.set(tag::NAME, use_name.as_bytes().to_vec());
                    let op = vault
                        .make_update(&rid, kind, item)
                        .map_err(|e| e.to_string())?;
                    mpm_store::append_op(dir, vault.device_id(), &op).map_err(|e| e.to_string())?;
                    vault.commit(&op).map_err(|e| e.to_string())?;
                    updated += 1;
                    break;
                }
                Some((_, Some(_))) => {
                    use_name = format!("{use_name}-imported");
                    continue;
                }
                _ => {
                    item.set(tag::NAME, use_name.as_bytes().to_vec());
                    let (op, _rid) = vault.make_upsert(kind, item).map_err(|e| e.to_string())?;
                    mpm_store::append_op(dir, vault.device_id(), &op).map_err(|e| e.to_string())?;
                    vault.commit(&op).map_err(|e| e.to_string())?;
                    created += 1;
                    break;
                }
            }
        }
        batch_names.insert(use_name);
    }
    save_checkpoint(&vault)?;
    eprintln!("imported {created} new, {updated} updated");
    Ok(())
}

/// Minimal RFC4180 reader: quoted fields, "" escapes, \r\n endings.
/// Input is attacker-ish (a foreign app's export) — strict UTF-8,
/// unclosed quotes rejected, never panics.
fn parse_csv(raw: &[u8]) -> Result<Vec<Vec<String>>, String> {
    let s = std::str::from_utf8(raw).map_err(|_| "csv is not valid UTF-8".to_string())?;
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut in_q = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if in_q {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => in_q = false,
                _ => field.push(c),
            }
        } else {
            match c {
                '"' if field.is_empty() => in_q = true,
                ',' => row.push(std::mem::take(&mut field)),
                '\n' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                }
                '\r' => {}
                _ => field.push(c),
            }
        }
    }
    if in_q {
        return Err("csv: unclosed quoted field".into());
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    Ok(rows)
}

/// Plaintext otpauth export (Ente, Aegis, 2FAS, Google takeout): URIs
/// separated by newlines, commas, or whitespace. We split at each
/// `otpauth://` marker and end a URI at the next separator — URI params
/// can only contain percent-encoded specials, never raw separators.
fn otpauth_to_items(raw: &[u8]) -> Result<Vec<(ItemKind, String, mpm_core::Item)>, String> {
    let text = std::str::from_utf8(raw).map_err(|_| "otpauth file isn't UTF-8")?;
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("otpauth://") {
        rest = &rest[start..];
        let end = rest
            .find(|c: char| c.is_whitespace() || c == ',')
            .unwrap_or(rest.len());
        let uri = &rest[..end];
        rest = &rest[end..];
        let oa = match mpm_core::totp::parse_otpauth(uri) {
            Ok(o) => o,
            // hotp:// and malformed lines warn+skip rather than abort the batch
            Err(e) => {
                eprintln!("warning: skipping otpauth entry {}: {e}", out.len() + 1);
                continue;
            }
        };
        let mut item = mpm_core::Item::default();
        item.set(tag::TOTP_SECRET, b32_encode(&oa.secret).into_bytes());
        item.set(tag::TOTP_DIGITS, oa.digits.to_string().into_bytes());
        item.set(tag::TOTP_PERIOD, oa.period.to_string().into_bytes());
        item.set(
            tag::TOTP_ALGO,
            format!("{:?}", oa.algo).to_uppercase().into_bytes(),
        );
        if !oa.issuer.is_empty() {
            item.set(tag::TOTP_ISSUER, oa.issuer.clone().into_bytes());
        }
        // label is usually "Issuer:account" already. A bare-account label
        // with a separate issuer param MUST become issuer:account — two
        // issuers both exporting "alice" would otherwise collide on the
        // same name and a later import would overwrite the earlier secret
        let name = if !oa.label.is_empty() {
            if !oa.issuer.is_empty()
                && oa.label != oa.issuer
                && !oa.label.starts_with(&format!("{}:", oa.issuer))
            {
                format!("{}:{}", oa.issuer, oa.label)
            } else {
                oa.label.clone()
            }
        } else if !oa.issuer.is_empty() {
            oa.issuer.clone()
        } else {
            format!("totp-{}", out.len() + 1)
        };
        let name: String = name.chars().filter(|c| !c.is_control()).collect();
        if name.is_empty() {
            continue;
        }
        out.push((ItemKind::Totp, name, item));
    }
    if out.is_empty() {
        return Err("no otpauth:// URIs found".into());
    }
    Ok(out)
}

/// Map Bitwarden/1Password-style CSV rows onto items. Header-driven;
/// unmapped columns are ignored; rows without any usable data are skipped.
fn csv_to_items(raw: &[u8]) -> Result<Vec<(ItemKind, String, mpm_core::Item)>, String> {
    // UTF-8 BOM (Excel/Windows exports) would corrupt the first header
    let raw = raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(raw);
    let rows = parse_csv(raw)?;
    let Some(hdr) = rows.first() else {
        return Err("empty csv".into());
    };
    let width = hdr.len();
    let col = |aliases: &[&str]| -> Option<usize> {
        hdr.iter()
            .position(|h| aliases.contains(&h.trim().to_lowercase().as_str()))
    };
    let c_name = col(&["name", "title", "item name"]);
    let c_user = col(&["username", "login_username", "user"]);
    let c_pass = col(&["password", "login_password"]);
    let c_url = col(&["url", "login_uri", "website", "urls"]);
    let c_totp = col(&["totp", "login_totp", "otpauth", "otp"]);
    let c_notes = col(&["notes", "note", "notesplain"]);
    let c_type = col(&["type", "item type", "item_type"]);
    let c_cnum = col(&["card_number", "number"]);
    let c_chold = col(&["cardholder", "cardholder_name", "holder", "cardholdername"]);
    let c_cexp = col(&["exp", "expiry", "expiration"]);
    let c_expm = col(&["expmonth", "exp_month"]);
    let c_expy = col(&["expyear", "exp_year"]);
    let c_ccvv = col(&["cvv", "csc", "security code", "code"]);

    let mut out = Vec::new();
    for (i, row) in rows.iter().skip(1).enumerate() {
        if row.iter().all(|c| c.is_empty()) {
            continue; // blank line
        }
        // shorter than the header is normal (missing trailing columns —
        // pad); LONGER means an unquoted comma broke the row — refusing
        // beats silently mapping fields into the wrong columns
        if row.len() > width {
            return Err(format!(
                "csv: row {} has {} cells, header has {width} — likely an unquoted comma",
                i + 1,
                row.len()
            ));
        }
        // data cells are NOT trimmed — a password may legitimately have
        // leading/trailing whitespace; only emptiness is filtered
        let pad = vec![String::new(); width.saturating_sub(row.len())];
        let row: Vec<&str> = row.iter().chain(&pad).map(|s| s.as_str()).collect();
        let g = |c: Option<usize>| -> Option<&str> {
            c.and_then(|j| row.get(j))
                .copied()
                .filter(|s| !s.is_empty())
        };
        let ty = g(c_type).unwrap_or("").to_lowercase();
        let mut item = mpm_core::Item::default();
        let mut kind = ItemKind::Login;
        if ty.contains("card") || g(c_cnum).is_some() {
            kind = ItemKind::Card;
        } else if ty.contains("note")
            || (g(c_user).is_none() && g(c_pass).is_none() && g(c_totp).is_none())
        {
            kind = ItemKind::Secret;
        } else if g(c_pass).is_none() && g(c_user).is_none() && g(c_totp).is_some() {
            kind = ItemKind::Totp;
        }
        let mut put = |t: u8, v: Option<&str>| {
            if let Some(v) = v {
                item.set(t, v.as_bytes().to_vec());
            }
        };
        put(tag::USERNAME, g(c_user));
        put(tag::PASSWORD, g(c_pass));
        put(tag::URL, g(c_url));
        put(tag::TOTP_SECRET, g(c_totp));
        put(tag::NOTES, g(c_notes));
        if kind == ItemKind::Secret {
            put(tag::TEXT, g(c_notes));
        }
        put(tag::CARD_NUMBER, g(c_cnum));
        put(tag::CARD_HOLDER, g(c_chold));
        put(tag::CARD_EXP, g(c_cexp));
        // Bitwarden exports exp as separate expMonth/expYear columns
        if g(c_cexp).is_none() {
            if let (Some(mo), Some(yr)) = (g(c_expm), g(c_expy)) {
                let yr = yr.strip_prefix("20").unwrap_or(yr);
                put(tag::CARD_EXP, Some(&format!("{mo:0>2}/{yr}")));
            }
        }
        put(tag::CARD_CVV, g(c_ccvv));
        if item.fields.is_empty() {
            continue; // row mapped to nothing — don't mint an empty Secret
        }
        let name = g(c_name)
            .or(g(c_user))
            .or(g(c_url))
            .map(|s| s.chars().filter(|c| !c.is_control()).collect::<String>())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("imported-{i}"));
        out.push((kind, name, item));
    }
    if out.is_empty() {
        return Err("no importable rows".into());
    }
    Ok(out)
}

// ── backup / restore ────────────────────────────────────────────────

/// Copy a file with mode 0600 and fsync — used for backup/restore of the
/// (already-encrypted) vault files.
fn copy_private(src: &Path, dst: &Path) -> Result<(), String> {
    let data = std::fs::read(src).map_err(|e| format!("read {}: {e}", src.display()))?;
    write_private_file(dst, &data)
}

fn mkdir_private(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|e| format!("mkdir {}: {e}", path.display()))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path).map_err(|e| format!("mkdir {}: {e}", path.display()))?;
    Ok(())
}

fn cmd_backup(dir: &Path, rec: bool, dest: &Path) -> Result<(), String> {
    // lock + full unlock: replay-verifying every op IS the backup integrity
    // check — we never copy bytes we couldn't authenticate
    let _lock = mpm_store::lock_vault(dir).map_err(|e| e.to_string())?;
    let vault = unlock(dir, rec)?;
    let (seq, _head) = vault.head();

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let out = dest.join(format!(
        "mypassman-backup-{ts}-{}",
        &mpm_store::hex(&vault.manifest.vault_id)[..8]
    ));
    mkdir_private(&out)?;
    mkdir_private(&out.join(mpm_store::OPS_DIR))?;
    copy_private(
        &dir.join(mpm_store::MANIFEST),
        &out.join(mpm_store::MANIFEST),
    )?;
    let mut nops = 0usize;
    let ops_dir = dir.join(mpm_store::OPS_DIR);
    if ops_dir.is_dir() {
        for e in std::fs::read_dir(&ops_dir).map_err(|e| e.to_string())? {
            let e = e.map_err(|e| e.to_string())?;
            if e.path().extension().is_some_and(|x| x == "log") {
                copy_private(&e.path(), &out.join(mpm_store::OPS_DIR).join(e.file_name()))?;
                nops += 1;
            }
        }
    }
    let f = std::fs::File::open(&out).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    eprintln!(
        "backup verified (seq {seq}) → {} ({} logs)",
        out.display(),
        nops
    );
    Ok(())
}

fn cmd_restore(dir: &Path, src: &Path) -> Result<(), String> {
    if !src.join(mpm_store::MANIFEST).is_file() {
        return Err(format!("{}: no MANIFEST — not a backup dir", src.display()));
    }
    if dir.join(mpm_store::MANIFEST).exists() {
        return Err(format!(
            "{} already holds a vault — pick an empty --vault dir",
            dir.display()
        ));
    }
    mkdir_private(dir)?;
    mkdir_private(&dir.join(mpm_store::OPS_DIR))?;
    copy_private(
        &src.join(mpm_store::MANIFEST),
        &dir.join(mpm_store::MANIFEST),
    )?;
    let mut n = 0usize;
    let src_ops = src.join(mpm_store::OPS_DIR);
    if src_ops.is_dir() {
        for e in std::fs::read_dir(&src_ops).map_err(|e| e.to_string())? {
            let e = e.map_err(|e| e.to_string())?;
            if e.path().extension().is_some_and(|x| x == "log") {
                copy_private(&e.path(), &dir.join(mpm_store::OPS_DIR).join(e.file_name()))?;
                n += 1;
            }
        }
    }
    // Deliberate rollback: the stored checkpoint may be ahead of this
    // snapshot. Clear it only around the verification — if the restore
    // fails, put the old checkpoint back so the previous vault's
    // rollback protection survives a bad/cancelled restore.
    let manifest = mpm_store::load_manifest(dir).map_err(|e| e.to_string())?;
    let old_ckpt = mpm_store::read_checkpoint_raw(&manifest.vault_id).map_err(|e| e.to_string())?;
    mpm_store::clear_checkpoint(&manifest.vault_id).map_err(|e| e.to_string())?;
    eprintln!("restored {n} logs → {}; verifying…", dir.display());
    let vault = match unlock(dir, false) {
        Ok(v) => v,
        Err(e) => {
            if let Some(b) = old_ckpt {
                let _ = mpm_store::write_checkpoint_raw(&manifest.vault_id, &b);
            }
            return Err(format!(
                "restore verify failed ({e}) — old checkpoint restored"
            ));
        }
    };
    save_checkpoint(&vault)?; // re-baseline to the restored head now
    eprintln!("restore verified — vault is live");
    Ok(())
}

// ── daemon / lock ───────────────────────────────────────────────────

fn cmd_daemon(dir: &Path, rec: bool, idle_ttl: Option<u64>) -> Result<(), String> {
    let ttl = idle_ttl
        .or_else(|| {
            std::env::var("MPM_IDLE_TTL")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(900);
    #[cfg(unix)]
    {
        daemon::run(dir, rec, ttl)
    }
    #[cfg(not(unix))]
    {
        let _ = (dir, rec, ttl);
        Err("daemon is unix-only for now — every command re-unlocks on this platform".into())
    }
}

fn cmd_lock(dir: &Path) -> Result<(), String> {
    match daemon::lock(dir)? {
        true => eprintln!("daemon locked"),
        false => eprintln!("no daemon running"),
    }
    Ok(())
}

// ── biometric unlock (macOS Touch ID) ───────────────────────────────

/// `bio enroll`: unlock with password → mint a random KEK → store it in
/// the Keychain gated by an LAContext prompt → wrap the bundle in a
/// SLOT_BIOMETRIC slot → re-sign the manifest.
#[cfg(target_os = "macos")]
fn cmd_bio_enroll(dir: &Path, rec: bool) -> Result<(), String> {
    if !bio::available() {
        return Err("no biometrics on this Mac (Touch ID unavailable/not enrolled)".into());
    }
    let _lock = mpm_store::lock_vault(dir).map_err(|e| e.to_string())?;
    // force the password path — enrolling biometrics must prove you know it
    let mut vault = if rec {
        unlock(dir, true)?
    } else {
        let keep = std::env::var_os("MPM_NO_BIO");
        std::env::set_var("MPM_NO_BIO", "1");
        let v = unlock(dir, false);
        match keep {
            Some(v2) => std::env::set_var("MPM_NO_BIO", v2),
            None => std::env::remove_var("MPM_NO_BIO"),
        }
        v?
    };

    let mut key = Zeroizing::new([0u8; bio::BIO_KEY_LEN]);
    rand_core_fill(&mut *key);
    bio::enroll(&vault.manifest.vault_id, &key)?;

    vault
        .manifest
        .wrap_slots
        .retain(|s| s.slot_type != SLOT_BIOMETRIC);
    vault.manifest.wrap_slots.push(WrapSlot {
        slot_type: SLOT_BIOMETRIC,
        kdf: None, // KEK is stored directly, no password KDF
        blob: vault
            .bundle()
            .wrap(
                &key,
                &mpm_core::aad::wrap_slot(
                    &vault.manifest.vault_id,
                    vault.manifest.key_epoch,
                    SLOT_BIOMETRIC,
                ),
            )
            .map_err(|e| e.to_string())?,
        extra: Vec::new(),
    });
    vault.manifest.snapshot_epoch += 1;
    let owner_sk = vault.bundle().owner_signing_key();
    let bytes = vault.manifest.to_file(&owner_sk);
    mpm_store::write_manifest(dir, &bytes).map_err(|e| e.to_string())?;
    eprintln!("Touch ID enrolled — unlocks now prompt for biometrics.");
    eprintln!("password still works ($MPM_NO_BIO=1 or --recovery to skip the prompt)");
    Ok(())
}

#[cfg(target_os = "macos")]
fn cmd_bio_off(dir: &Path, rec: bool) -> Result<(), String> {
    let _lock = mpm_store::lock_vault(dir).map_err(|e| e.to_string())?;
    let mut vault = unlock(dir, rec)?; // bio path ok — you own the fingers
    bio::remove(&vault.manifest.vault_id);
    vault
        .manifest
        .wrap_slots
        .retain(|s| s.slot_type != SLOT_BIOMETRIC);
    vault.manifest.snapshot_epoch += 1;
    let owner_sk = vault.bundle().owner_signing_key();
    let bytes = vault.manifest.to_file(&owner_sk);
    mpm_store::write_manifest(dir, &bytes).map_err(|e| e.to_string())?;
    eprintln!("biometric unlock removed");
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn cmd_bio_enroll(_dir: &Path, _rec: bool) -> Result<(), String> {
    Err("biometric unlock is macOS-only so far (Windows Hello / secret-service come with those ports)".into())
}

#[cfg(not(target_os = "macos"))]
fn cmd_bio_off(_dir: &Path, _rec: bool) -> Result<(), String> {
    Err("no biometric enrollment on this platform".into())
}

fn main() {
    let cli = Cli::parse();
    let dir = vault_dir(&cli);
    let rec = cli.recovery;
    let res = match &cli.cmd {
        Cmd::Init => cmd_init(&dir),
        Cmd::Add { kind, name, fields } => cmd_add(&dir, rec, kind, name, fields),
        Cmd::Get {
            name,
            show,
            copy,
            paste,
            r#type,
        } => pick_out(copy.as_ref(), paste.as_ref(), r#type)
            .and_then(|out| cmd_get(&dir, rec, name, *show, &out)),
        Cmd::List { json } => cmd_list(&dir, rec, *json),
        Cmd::Rm { name } => cmd_rm(&dir, rec, name),
        Cmd::History { name, json } => cmd_history(&dir, rec, name, *json),
        Cmd::Devices => cmd_devices(&dir, cli.recovery),
        Cmd::Passwd => cmd_passwd(&dir, rec),
        Cmd::Recovery { sub } => match sub {
            RecoveryCmd::Rotate => cmd_recovery_rotate(&dir, rec),
        },
        Cmd::Gen {
            len,
            passphrase,
            no_symbols,
            copy,
        } => cmd_gen(*len, *passphrase, *no_symbols, *copy),
        Cmd::Otp {
            name,
            copy,
            paste,
            r#type,
        } => {
            let s = String::new();
            pick_out(
                copy.then_some(&s),
                paste.then_some(&s),
                if *r#type {
                    std::slice::from_ref(&s)
                } else {
                    &[]
                },
            )
            .and_then(|out| cmd_otp(&dir, rec, name, &out))
        }
        Cmd::Edit { name, fields } => cmd_edit(&dir, rec, name, fields),
        Cmd::Run { inject, cmd } => cmd_run(&dir, rec, inject, cmd),
        Cmd::Clipclear => cmd_clipclear(),
        Cmd::Preflight => autofill_preflight().map(|_| println!("ok")),
        Cmd::Dopaste { id, field, otp } => cmd_dopaste(&dir, rec, id, field.as_ref(), *otp),
        Cmd::Export { path } => cmd_export(&dir, rec, path),
        Cmd::Import {
            path,
            csv,
            otpauth,
            dry_run,
        } => cmd_import(&dir, rec, path, *csv, *otpauth, *dry_run),
        Cmd::Backup { dest } => cmd_backup(&dir, rec, dest),
        Cmd::Restore { src } => cmd_restore(&dir, src),
        Cmd::Daemon { idle_ttl } => cmd_daemon(&dir, rec, *idle_ttl),
        Cmd::Ping => {
            if daemon::alive(&dir) {
                Ok(())
            } else {
                Err("locked".into())
            }
        }
        Cmd::Lock => cmd_lock(&dir),
        Cmd::Bio { sub } => match sub {
            BioCmd::Enroll => cmd_bio_enroll(&dir, rec),
            BioCmd::Off => cmd_bio_off(&dir, rec),
        },
        Cmd::Sync { sub } => match sub {
            Some(SyncCmd::Init { url, setup_key }) => sync::cmd_sync_init(&dir, url, setup_key),
            None => sync::cmd_sync(&dir),
        },
        Cmd::Pair { sub } => match sub {
            PairCmd::Invite { qr } => sync::cmd_pair_invite(&dir, *qr),
            PairCmd::Pending => sync::cmd_pair_pending(&dir),
            PairCmd::Approve { device } => sync::cmd_pair_approve(&dir, rec, device),
            PairCmd::Decline { device } => sync::cmd_pair_decline(&dir, device),
            PairCmd::Join { url, invite, name } => sync::cmd_pair_join(&dir, url, invite, name),
            PairCmd::Finish => sync::cmd_pair_finish(&dir),
            PairCmd::Revoke { device, keep_keys } => {
                sync::cmd_pair_revoke(&dir, rec, device, *keep_keys)
            }
        },
    };

    if let Err(e) = res {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_quotes_and_commas() {
        let rows = parse_csv(b"a,\"b,c\",d\r\n1,2,3\nlast,,\"x\"\"y\"").unwrap();
        assert_eq!(rows[0], vec!["a", "b,c", "d"]);
        assert_eq!(rows[1], vec!["1", "2", "3"]);
        assert_eq!(rows[2], vec!["last", "", "x\"y"]);
    }

    #[test]
    fn csv_maps_bitwarden_and_1p() {
        let bw = b"folder,type,name,login_uri,login_username,login_password,login_totp,notes\n,login,GH,https://github.com,u,pw,JBSWY3DPEHPK3PXP,n1\n";
        let items = csv_to_items(bw).unwrap();
        assert_eq!(items.len(), 1);
        let (kind, name, it) = &items[0];
        assert_eq!(*kind, ItemKind::Login);
        assert_eq!(name, "GH");
        assert_eq!(it.get_str(tag::PASSWORD), Some("pw"));
        assert_eq!(it.get_str(tag::TOTP_SECRET), Some("JBSWY3DPEHPK3PXP"));

        // 1Password-style headers + a card row + a note row
        let op = b"Title,Type,Username,Password,Url,Number,CVV,Notes\nV,card,,,,4111,999,\nN,note,,,,,,sekrit\n";
        let items = csv_to_items(op).unwrap();
        assert_eq!(items[0].0, ItemKind::Card);
        assert_eq!(items[0].2.get_str(tag::CARD_NUMBER), Some("4111"));
        assert_eq!(items[1].0, ItemKind::Secret);
        assert_eq!(items[1].2.get_str(tag::TEXT), Some("sekrit"));
    }
}
