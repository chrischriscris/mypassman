//! mypassman CLI — v0: init/add/get/list/rm/devices on a single device.
//! Daemon + agent mode land at M2.

use clap::{Parser, Subcommand};
use mpm_core::item::{tag, Item, ItemKind};
use mpm_core::manifest::{WrapSlot, SLOT_PASSWORD, SLOT_RECOVERY};
use mpm_core::{gen, recovery, Manifest, Vault};
use mpm_crypto::kdf::{self, KdfParams};
use mpm_crypto::keys::{DeviceKey, KeyBundle};
mod daemon;

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
    },
    /// List items (names + kinds only — fields stay sealed)
    #[command(alias = "ls")]
    List,
    /// Tombstone an item
    Rm { name: String },
    /// Show enrolled devices
    Devices,
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
    /// Export all items to a passphrase-sealed portable file (MPMEXP).
    /// The export passphrase is prompted (or $MPM_EXPORT_PASSWORD).
    Export { path: PathBuf },
    /// Import items. Default: an MPMEXP sealed export; --csv reads a
    /// Bitwarden/1Password-style CSV export (login/card/note rows).
    Import {
        path: PathBuf,
        /// treat input as CSV instead of MPMEXP
        #[arg(long)]
        csv: bool,
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
}

#[derive(Subcommand)]
enum RecoveryCmd {
    /// Mint a new recovery code (requires master password); invalidates the old kit
    Rotate,
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
        ("notes", tag::NOTES, false),
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
fn read_password(prompt: &str) -> Zeroizing<String> {
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

    let (slot_type, secret) = if recovery_mode {
        let code = read_password("recovery code: ");
        let raw = recovery::parse_code(&code).map_err(|_| "malformed recovery code".to_string())?;
        (SLOT_RECOVERY, Zeroizing::new(raw.to_vec()))
    } else {
        let pw = read_password("master password: ");
        (SLOT_PASSWORD, Zeroizing::new(pw.as_bytes().to_vec()))
    };

    let mut bundle = None;
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
        let kek = kdf::derive_kek(&secret, salt, params).map_err(|e| e.to_string())?;
        if let Ok(b) = KeyBundle::unwrap(
            &kek,
            &mpm_core::aad::wrap_slot(&manifest.vault_id, manifest.key_epoch, slot_type),
            &slot.blob,
        ) {
            bundle = Some(b);
            break;
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
                extra: Vec::new(),
            });
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
        let pts = vault
            .verify_foreign_log(&dev_id, &lr.ops)
            .map_err(|e| e.to_string())?;
        vault.apply_foreign(pts);
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
        daemon::DaemonItem::Found(mut item, Some(k), rec_name) => {
            if k != kind {
                return Err(format!(
                    "'{name}' exists as {} — rm it first to change kind",
                    k.name()
                ));
            }
            for (t, v) in given.values() {
                item.set(*t, v.clone().into_bytes());
            }
            item.set(tag::NAME, rec_name.into_bytes()); // NAME is outer-layer
            for (fname, secret) in required_fields(kind) {
                let t = fmap[*fname].0;
                if *secret && item.get(t).is_none() {
                    item.set(t, prompt_secret(fname).as_bytes().to_vec());
                }
            }
            item.set(tag::NAME, name.as_bytes().to_vec());
            finalize_totp(&mut item)?;
            let Some((rid, _)) = daemon::try_put(dir, kind, name, &item)? else {
                return Err("daemon vanished mid-add".into());
            };
            eprintln!("updated '{}' ({})", name, mpm_store::hex(&rid));
            return Ok(());
        }
        daemon::DaemonItem::Found(_, None, _) => {
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
            let Some((rid, _)) = daemon::try_put(dir, kind, name, &item)? else {
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

fn cmd_list(dir: &Path, rec: bool) -> Result<(), String> {
    println!("{:<10} {:<40} ID", "KIND", "NAME");
    if let Some(rows) = daemon::try_list(dir)? {
        for (kind, name, rid) in rows {
            println!(
                "{:<10} {:<40} {}",
                kind.map(|k| k.name()).unwrap_or("-"),
                name,
                rid
            );
        }
        return Ok(());
    }
    let vault = unlock(dir, rec)?;
    let mut rows: Vec<_> = vault.records().collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    for r in rows {
        println!(
            "{:<10} {:<40} {}",
            r.kind.map(|k| k.name()).unwrap_or("-"),
            r.name,
            mpm_store::hex(&r.record_id)
        );
    }
    Ok(())
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

fn cmd_get(
    dir: &Path,
    rec: bool,
    name: &str,
    show: bool,
    copy: &Option<String>,
) -> Result<(), String> {
    match daemon::item(dir, name)? {
        daemon::DaemonItem::Found(item, _, _) => return render_item(&item, show, copy),
        daemon::DaemonItem::Missing => return Err(format!("'{name}': not found")),
        daemon::DaemonItem::Offline => {}
    }
    let vault = unlock(dir, rec)?;
    let rid = find_one(&vault, name)?;
    let item = vault.item(&rid).map_err(|e| e.to_string())?;
    render_item(&item, show, copy)
}

fn render_item(item: &mpm_core::Item, show: bool, copy: &Option<String>) -> Result<(), String> {
    let fmap = field_map();
    let inv: BTreeMap<u8, (&str, bool)> = fmap.iter().map(|(n, (t, s))| (*t, (*n, *s))).collect();

    if let Some(field) = copy {
        let Some((t, _)) = fmap.get(field.as_str()) else {
            return Err(format!("unknown field '{field}'"));
        };
        let val = item.get(*t).ok_or("field absent")?;
        copy_to_clipboard(val)?;
        eprintln!(
            "copied '{field}' — concealed from clipboard managers, auto-clears in {}s",
            clip_ttl()
        );
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

/// `otp <name>` — current TOTP code for any item carrying a totp_secret
/// (a login can hold its own 2FA; a `totp` item is the standalone form).
fn cmd_otp(dir: &Path, rec: bool, name: &str, copy: bool) -> Result<(), String> {
    let item = match daemon::item(dir, name)? {
        daemon::DaemonItem::Found(i, _, _) => i,
        daemon::DaemonItem::Missing => return Err(format!("'{name}': not found")),
        daemon::DaemonItem::Offline => {
            let vault = unlock(dir, rec)?;
            let rid = find_one(&vault, name)?;
            vault.item(&rid).map_err(|e| e.to_string())?
        }
    };
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
    let (code, left) = mpm_core::totp::totp(&secret, now, period, digits, algo);
    if copy {
        copy_to_clipboard(code.as_bytes())?;
        eprintln!("copied code — auto-clears in {}s", clip_ttl());
    } else {
        println!("{code}  (valid {left}s more)");
    }
    Ok(())
}

/// `edit <name> -f field=val …` — update fields on an EXISTING item.
/// Unlike `add` it refuses to create: typos can't spawn stray records.
fn cmd_edit(dir: &Path, rec: bool, name: &str, cli_fields: &[String]) -> Result<(), String> {
    if cli_fields.is_empty() {
        return Err("nothing to change — pass -f field=value".into());
    }
    if let daemon::DaemonItem::Found(mut item, kind, rec_name) = daemon::item(dir, name)? {
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
        item.set(tag::NAME, rec_name.into_bytes()); // NAME is outer-layer — re-inject
        finalize_totp(&mut item)?;
        let Some(kind) = kind else {
            return Err("daemon: record kind unknown".into());
        };
        let Some((rid, _)) = daemon::try_put(dir, kind, name, &item)? else {
            return Err("daemon vanished mid-edit".into());
        };
        eprintln!("updated '{name}' ({})", mpm_store::hex(&rid));
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
    mpm_store::append_op(dir, vault.device_id(), &op).map_err(|e| e.to_string())?;
    vault.commit(&op).map_err(|e| e.to_string())?;
    save_checkpoint(&vault)?;
    eprintln!("updated '{}' ({})", name, mpm_store::hex(&rid));
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
        let Some((iname, fname)) = itempart.split_once(':') else {
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
    c.args(&cmd[1..]).env_remove("MPM_PASSWORD");

    if daemon::alive(dir) {
        for spec in &specs {
            let daemon::DaemonItem::Found(item, _, _) = daemon::item(dir, &spec.iname)? else {
                return Err(format!("'{}': not found", spec.iname));
            };
            let val = item
                .get(spec.tag)
                .ok_or(format!("'{}' has no such field", spec.iname))?;
            c.env(&spec.envvar, String::from_utf8_lossy(val).into_owned());
        }
    } else {
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
        .stderr(Stdio::null())
        .env_remove("MPM_PASSWORD");
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
    let mut p = Command::new("osascript")
        .args(["-l", "JavaScript", "-e", JXA])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .env_remove("MPM_PASSWORD")
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
        let _ = std::process::Command::new("osascript")
            .args(["-l", "JavaScript", "-e", &script])
            .env_remove("MPM_PASSWORD")
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
        if let Ok(mut p) = Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .env_remove("MPM_PASSWORD")
            .spawn()
        {
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
    std::process::Command::new("pbpaste")
        .env_remove("MPM_PASSWORD")
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
        if let Ok(o) = std::process::Command::new(cmd).args(args).output() {
            if o.status.success() {
                return Some(o.stdout);
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn clip_read() -> Option<Vec<u8>> {
    std::process::Command::new("powershell")
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
        if let Ok(st) = std::process::Command::new(cmd).args(args).status() {
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

fn rand_core_fill(b: &mut [u8]) {
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, b);
}

// ── export / import ─────────────────────────────────────────────────

/// Export passphrase: $MPM_EXPORT_PASSWORD (consumed) or a TTY/stdin
/// prompt. Distinct from the vault password on purpose — an export blob
/// must not inherit the vault's slot semantics.
fn export_passphrase(confirm: bool) -> Result<Zeroizing<String>, String> {
    if let Ok(p) = std::env::var("MPM_EXPORT_PASSWORD") {
        std::env::remove_var("MPM_EXPORT_PASSWORD");
        return Ok(Zeroizing::new(p));
    }
    let p = read_password("export passphrase: ");
    if confirm {
        let p2 = read_password("confirm passphrase: ");
        if p.as_str() != p2.as_str() {
            return Err("passphrases don't match".into());
        }
    }
    if p.is_empty() {
        return Err("empty passphrase".into());
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
    for r in vault.records() {
        let Some(kind) = r.kind else { continue };
        let item = vault.item(&r.record_id).map_err(|e| e.to_string())?;
        recs.push(mpm_core::export::ExportRecord {
            kind,
            name: r.name.clone(),
            fields: item.encode(),
        });
    }
    let blob = mpm_core::export::seal_export(&recs, pw.as_bytes()).map_err(|e| e.to_string())?;
    write_private_file(path, &blob)?;
    eprintln!("exported {} records → {}", recs.len(), path.display());
    Ok(())
}

fn cmd_import(dir: &Path, rec: bool, path: &Path, csv: bool) -> Result<(), String> {
    let _lock = mpm_store::lock_vault(dir).map_err(|e| e.to_string())?;
    let mut vault = unlock(dir, rec)?;
    let items: Vec<(ItemKind, String, mpm_core::Item)> = if csv {
        let raw = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        csv_to_items(&raw)?
    } else {
        let blob = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let pw = export_passphrase(false)?;
        let recs =
            mpm_core::export::open_export(&blob, pw.as_bytes()).map_err(|e| e.to_string())?;
        recs.iter()
            .map(|r| {
                Item::decode(&r.fields)
                    .map(|it| (r.kind, r.name.clone(), it))
                    .map_err(|e| e.to_string())
            })
            .collect::<Result<_, _>>()?
    };

    let mut created = 0usize;
    let mut updated = 0usize;
    for (kind, name, mut item) in items {
        item.set(tag::NAME, name.as_bytes().to_vec());
        finalize_totp(&mut item)?;
        // same name + same kind → replace; name taken by another kind →
        // find a free suffix rather than minting an ambiguous duplicate
        let mut use_name = name.clone();
        loop {
            let existing = vault
                .records()
                .find(|r| r.name == use_name)
                .map(|r| (r.record_id, r.kind));
            match existing {
                Some((rid, Some(k))) if k == kind => {
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
    }
    save_checkpoint(&vault)?;
    eprintln!("imported {created} new, {updated} updated");
    Ok(())
}

/// Minimal RFC4180 reader: quoted fields, "" escapes, \r\n endings.
/// Input is attacker-ish (a foreign app's export) — lenient, never panics.
fn parse_csv(raw: &[u8]) -> Vec<Vec<String>> {
    let s = String::from_utf8_lossy(raw);
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
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// Map Bitwarden/1Password-style CSV rows onto items. Header-driven;
/// unmapped columns are ignored; rows without any usable data are skipped.
fn csv_to_items(raw: &[u8]) -> Result<Vec<(ItemKind, String, mpm_core::Item)>, String> {
    let rows = parse_csv(raw);
    let Some(hdr) = rows.first() else {
        return Err("empty csv".into());
    };
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
    let c_chold = col(&["cardholder", "cardholder_name", "holder"]);
    let c_cexp = col(&["exp", "expiry", "expiration"]);
    let c_ccvv = col(&["cvv", "csc", "security code"]);

    let mut out = Vec::new();
    for (i, row) in rows.iter().skip(1).enumerate() {
        let g = |c: Option<usize>| -> Option<&str> {
            c.and_then(|j| row.get(j))
                .map(|s| s.trim())
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
        put(tag::CARD_CVV, g(c_ccvv));
        let name = g(c_name)
            .or(g(c_user))
            .or(g(c_url))
            .map(|s| s.to_string())
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
    // deliberate rollback: the stored checkpoint may be ahead of this
    // snapshot — re-baseline AFTER the copy verifies (unlock re-saves it)
    let manifest = mpm_store::load_manifest(dir).map_err(|e| e.to_string())?;
    mpm_store::clear_checkpoint(&manifest.vault_id).map_err(|e| e.to_string())?;
    eprintln!("restored {n} logs → {}; verifying…", dir.display());
    let _vault = unlock(dir, false)?; // replay-verify; failures surface here
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

fn main() {
    let cli = Cli::parse();
    let dir = vault_dir(&cli);
    let rec = cli.recovery;
    let res = match &cli.cmd {
        Cmd::Init => cmd_init(&dir),
        Cmd::Add { kind, name, fields } => cmd_add(&dir, rec, kind, name, fields),
        Cmd::Get { name, show, copy } => cmd_get(&dir, rec, name, *show, copy),
        Cmd::List => cmd_list(&dir, rec),
        Cmd::Rm { name } => cmd_rm(&dir, rec, name),
        Cmd::Devices => cmd_devices(&dir, cli.recovery),
        Cmd::Recovery { sub } => match sub {
            RecoveryCmd::Rotate => cmd_recovery_rotate(&dir, rec),
        },
        Cmd::Gen {
            len,
            passphrase,
            no_symbols,
            copy,
        } => cmd_gen(*len, *passphrase, *no_symbols, *copy),
        Cmd::Otp { name, copy } => cmd_otp(&dir, rec, name, *copy),
        Cmd::Edit { name, fields } => cmd_edit(&dir, rec, name, fields),
        Cmd::Run { inject, cmd } => cmd_run(&dir, rec, inject, cmd),
        Cmd::Clipclear => cmd_clipclear(),
        Cmd::Export { path } => cmd_export(&dir, rec, path),
        Cmd::Import { path, csv } => cmd_import(&dir, rec, path, *csv),
        Cmd::Backup { dest } => cmd_backup(&dir, rec, dest),
        Cmd::Restore { src } => cmd_restore(&dir, src),
        Cmd::Daemon { idle_ttl } => cmd_daemon(&dir, rec, *idle_ttl),
        Cmd::Lock => cmd_lock(&dir),
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
        let rows = parse_csv(b"a,\"b,c\",d\r\n1,2,3\nlast,,\"x\"\"y\"");
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
