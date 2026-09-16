//! mypassman CLI — v0: init/add/get/list/rm/devices on a single device.
//! Daemon + agent mode land at M2.

use clap::{Parser, Subcommand};
use mpm_core::item::{tag, Item, ItemKind};
use mpm_core::manifest::{WrapSlot, SLOT_PASSWORD, SLOT_RECOVERY};
use mpm_core::{gen, recovery, Manifest, Vault};
use mpm_crypto::kdf::{self, KdfParams};
use mpm_crypto::keys::{DeviceKey, KeyBundle};
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
    /// (internal) clipboard janitor — spawned detached, clears clipboard
    /// after TTL iff it still holds our payload. Hash arrives on stdin.
    #[command(hide = true, name = "__clipclear")]
    Clipclear,
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

fn cmd_list(dir: &Path, rec: bool) -> Result<(), String> {
    let vault = unlock(dir, rec)?;
    let mut rows: Vec<_> = vault.records().collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    println!("{:<10} {:<40} ID", "KIND", "NAME");
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
    let vault = unlock(dir, rec)?;
    let rid = find_one(&vault, name)?;
    let item = vault.item(&rid).map_err(|e| e.to_string())?;
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
        Cmd::Clipclear => cmd_clipclear(),
    };
    if let Err(e) = res {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
