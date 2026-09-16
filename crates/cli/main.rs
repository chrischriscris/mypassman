//! mypassman CLI — v0: init/add/get/list/rm/devices on a single device.
//! Daemon + agent mode land at M2.

use clap::{Parser, Subcommand};
use mpm_core::item::{tag, Item, ItemKind};
use mpm_core::manifest::{WrapSlot, SLOT_PASSWORD, SLOT_RECOVERY};
use mpm_core::{gen, recovery, Manifest, Vault};
use mpm_crypto::keys::{DeviceKey, KeyBundle};
use mpm_crypto::kdf::{self, KdfParams};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const DEVICE_KDF_CAP_KIB: u32 = 1_048_576; // 1 GiB desktop cap

#[derive(Parser)]
#[command(name = "mypassman", version, about = "local-first E2EE password manager")]
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
        /// length (charset mode) or word count (--passphrase)
        #[arg(short, long, default_value_t = 20)]
        len: usize,
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
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

fn field_map() -> BTreeMap<&'static str, (u8, bool)> {
    // name -> (tag, is_secret)
    let mut m = BTreeMap::new();
    for (n, t, s) in [
        ("username", tag::USERNAME, false), ("password", tag::PASSWORD, true),
        ("url", tag::URL, false), ("notes", tag::NOTES, false),
        ("number", tag::CARD_NUMBER, true), ("exp", tag::CARD_EXP, false),
        ("cvv", tag::CARD_CVV, true), ("holder", tag::CARD_HOLDER, false),
        ("pin", tag::CARD_PIN, true),
        ("key", tag::KEY, true), ("secret", tag::KEY_SECRET, true),
        ("endpoint", tag::ENDPOINT, false), ("env", tag::ENV, false),
        ("expires", tag::EXPIRES, false),
        ("totp_secret", tag::TOTP_SECRET, true), ("issuer", tag::TOTP_ISSUER, false),
        ("digits", tag::TOTP_DIGITS, false), ("period", tag::TOTP_PERIOD, false),
        ("text", tag::TEXT, true),
        ("full_name", tag::FULL_NAME, false), ("address", tag::ADDRESS, false),
        ("phone", tag::PHONE, false), ("email", tag::EMAIL, false),
        ("private", tag::SSH_PRIVATE, true), ("public", tag::SSH_PUBLIC, false),
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

fn prompt_secret(what: &str) -> Zeroizing<String> {
    read_password(&format!("{what}: "))
}

/// TTY prompt → $MPM_PASSWORD (scripting) → stdin fallback.
fn read_password(prompt: &str) -> Zeroizing<String> {
    if let Ok(p) = std::env::var("MPM_PASSWORD") {
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

/// Open vault: manifest → password (or recovery code) → try slots → replay logs.
fn unlock(dir: &Path, recovery_mode: bool) -> Result<Vault, String> {
    let manifest = mpm_store::load_manifest(dir).map_err(|e| e.to_string())?;
    manifest.kdf.check_bounds(DEVICE_KDF_CAP_KIB).map_err(|e| e.to_string())?;
    let device = mpm_store::load_device_key(&manifest.vault_id).map_err(|e| e.to_string())?;

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
        let Some((params, salt)) = &slot.kdf else { continue };
        params.check_bounds(DEVICE_KDF_CAP_KIB).map_err(|e| e.to_string())?;
        let kek = kdf::derive_kek(&secret, salt, params).map_err(|e| e.to_string())?;
        if let Ok(b) = KeyBundle::unwrap(&kek, &mpm_core::aad::wrap_slot(slot_type), &slot.blob) {
            bundle = Some(b);
            break;
        }
    }
    let bundle = bundle.ok_or("unlock failed")?;
    let mut vault = Vault::new(manifest, bundle, device).map_err(|e| e.to_string())?;

    // replay own log
    let ops = mpm_store::read_ops(dir, vault.device_id()).map_err(|e| e.to_string())?;
    for op in &ops {
        vault.apply_own_op(op).map_err(|e| e.to_string())?;
    }
    // replay foreign logs (verify + merge)
    for dev_id in mpm_store::list_device_logs(dir).map_err(|e| e.to_string())? {
        if &dev_id == vault.device_id() {
            continue;
        }
        let ops = mpm_store::read_ops(dir, &dev_id).map_err(|e| e.to_string())?;
        let pts = vault.verify_foreign_log(&dev_id, &ops).map_err(|e| e.to_string())?;
        vault.apply_foreign(pts);
    }
    Ok(vault)
}

fn cmd_init(dir: &Path) -> Result<(), String> {
    mpm_store::init_dir(dir).map_err(|e| e.to_string())?;
    let pw = read_password("new master password: ");
    let pw2 = read_password("confirm: ");
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
            .wrap(&kek, &mpm_core::aad::wrap_slot(SLOT_PASSWORD))
            .map_err(|e| e.to_string())?,
    });
    manifest.devices.push(mpm_core::DeviceEntry {
        id: device.id,
        vk: device.verifying_key(),
        name: "this device".into(),
        active: true,
        enrolled_at: mpm_core::vault::now_hlc(),
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
            .wrap(&rkek, &mpm_core::aad::wrap_slot(SLOT_RECOVERY))
            .map_err(|e| e.to_string())?,
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

fn cmd_add(dir: &Path, rec: bool, kind: &str, name: &str, cli_fields: &[String]) -> Result<(), String> {
    let kind = ItemKind::from_name(kind).map_err(|_| format!("unknown kind '{kind}'"))?;
    let fmap = field_map();
    let mut item = Item::default();
    item.set(tag::NAME, name.as_bytes().to_vec());

    // Unlock before touching secrets — prompts happen on an open vault.
    let mut vault = unlock(dir, rec)?;

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

    // prompt for missing required fields
    for (fname, secret) in required_fields(kind) {
        if given.contains_key(*fname) {
            continue;
        }
        let val = if *secret {
            prompt_secret(fname).as_str().to_string()
        } else {
            let v = read_line(fname);
            if v.is_empty() {
                continue;
            }
            v
        };
        if !val.is_empty() {
            given.insert(fname.to_string(), (fmap[fname].0, val));
        }
    }

    for (_, (t, v)) in given {
        item.set(t, v.into_bytes());
    }

    let (op, rid) = vault.make_upsert(kind, item).map_err(|e| e.to_string())?;
    mpm_store::append_op(dir, vault.device_id(), &op).map_err(|e| e.to_string())?;
    vault.commit(&op).map_err(|e| e.to_string())?;
    eprintln!("added {} '{}' ({})", kind.name(), name, mpm_store::hex(&rid));
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

fn cmd_get(dir: &Path, rec: bool, name: &str, show: bool, copy: &Option<String>) -> Result<(), String> {
    let vault = unlock(dir, rec)?;
    let rid = vault.find(name).ok_or("not found (or ambiguous)")?;
    let item = vault.item(&rid).map_err(|e| e.to_string())?;
    let fmap = field_map();
    let inv: BTreeMap<u8, (&str, bool)> = fmap.iter().map(|(n, (t, s))| (*t, (*n, *s))).collect();

    if let Some(field) = copy {
        let Some((t, _)) = fmap.get(field.as_str()) else {
            return Err(format!("unknown field '{field}'"));
        };
        let val = item.get(*t).ok_or("field absent")?;
        copy_to_clipboard(val)?;
        eprintln!("copied '{field}' — concealed from clipboard managers, auto-clears in {}s", clip_ttl());
        return Ok(());
    }

    for (t, vals) in &item.fields {
        let (fname, secret) = inv.get(t).copied().unwrap_or(("field", false));
        for v in vals {
            let text = String::from_utf8_lossy(v);
            if secret && !show {
                println!("{fname}: ********");
            } else {
                println!("{fname}: {text}");
            }
        }
    }
    Ok(())
}

fn cmd_rm(dir: &Path, rec: bool, name: &str) -> Result<(), String> {
    let mut vault = unlock(dir, rec)?;
    let rid = vault.find(name).ok_or("not found (or ambiguous)")?;
    let op = vault.make_tombstone(&rid).map_err(|e| e.to_string())?;
    mpm_store::append_op(dir, vault.device_id(), &op).map_err(|e| e.to_string())?;
    vault.commit(&op).map_err(|e| e.to_string())?;
    eprintln!("deleted '{name}' (tombstoned)");
    Ok(())
}

fn cmd_recovery_rotate(dir: &Path, rec: bool) -> Result<(), String> {
    let mut vault = unlock(dir, rec)?;
    let raw_code = recovery::generate_code();
    let params = KdfParams::default();
    let mut rsalt = [0u8; 32];
    rand_core_fill(&mut rsalt);
    let rkek = kdf::derive_kek(&raw_code, &rsalt, &params).map_err(|e| e.to_string())?;

    vault.manifest.wrap_slots.retain(|s| s.slot_type != SLOT_RECOVERY);
    vault.manifest.wrap_slots.push(WrapSlot {
        slot_type: SLOT_RECOVERY,
        kdf: Some((params, rsalt)),
        blob: vault
            .bundle()
            .wrap(&rkek, &mpm_core::aad::wrap_slot(SLOT_RECOVERY))
            .map_err(|e| e.to_string())?,
    });
    let owner_sk = vault.bundle().owner_signing_key();
    let bytes = vault.manifest.to_file(&owner_sk);
    mpm_store::write_manifest(dir, &bytes).map_err(|e| e.to_string())?;

    eprintln!("=== NEW RECOVERY KIT — old code is now useless. ===");
    eprintln!("  code:      {}", recovery::format_code(&raw_code));
    eprintln!("  key_epoch: {}", vault.manifest.key_epoch);
    Ok(())
}

fn cmd_gen(len: usize, passphrase: bool, no_symbols: bool, copy: bool) -> Result<(), String> {
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
        eprintln!("copied — concealed from clipboard managers, auto-clears in {}s", clip_ttl());
    } else {
        println!("{}", out.as_str());
    }
    Ok(())
}

fn cmd_devices(dir: &Path) -> Result<(), String> {
    let manifest = mpm_store::load_manifest(dir).map_err(|e| e.to_string())?;
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

#[cfg(target_os = "macos")]
fn copy_to_clipboard(val: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // NSPasteboard via JXA: writes the string AND marks the item
    // org.nspasteboard.ConcealedType + AutoGeneratedType — the convention
    // Raycast/Maccy/Paste honor by skipping the item in history.
    // Payload arrives on stdin: never in argv, env, or the script text.
    const JXA: &str = r#"
ObjC.import('AppKit');
var d = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
var s = $.NSString.alloc.initWithDataEncoding(d, $.NSUTF8StringEncoding).js;
var pb = $.NSPasteboard.generalPasteboard;
pb.clearContents;
var it = $.NSPasteboardItem.alloc.init;
it.setStringForType(s, 'public.utf8-plain-text');
it.setDataForType($.NSData.data, 'org.nspasteboard.ConcealedType');
it.setDataForType($.NSData.data, 'org.nspasteboard.AutoGeneratedType');
pb.writeObjects($([it]));
"#;
    let mut p = Command::new("osascript")
        .args(["-l", "JavaScript", "-e", JXA])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    p.stdin.take().unwrap().write_all(val).map_err(|e| e.to_string())?;
    if !p.wait().map_err(|e| e.to_string())?.success() {
        return Err("clipboard write failed".into());
    }

    // detached janitor: gets the payload hash on stdin, clears clipboard
    // after TTL iff unchanged (won't clobber something you copied later)
    let hash = blake3::hash(val).to_hex().to_string();
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut c = Command::new(exe)
        .arg("__clipclear")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Some(mut s) = c.stdin.take() {
        let _ = s.write_all(hash.as_bytes());
    }
    Ok(())
}

/// Janitor body: sleep, then clear iff clipboard still holds our payload.
fn cmd_clipclear() -> Result<(), String> {
    use std::io::Read;
    let mut hash = String::new();
    std::io::stdin().read_to_string(&mut hash).map_err(|e| e.to_string())?;
    std::thread::sleep(std::time::Duration::from_secs(clip_ttl()));
    if let Ok(out) = std::process::Command::new("pbpaste").output() {
        if out.status.success()
            && blake3::hash(&out.stdout).to_hex().as_str() == hash.trim()
        {
            let _ = std::process::Command::new("sh")
                .args(["-c", "pbcopy < /dev/null"])
                .status();
        }
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn copy_to_clipboard(val: &[u8]) -> Result<(), String> {
    use std::io::Write;
    for cmd in ["wl-copy", "xclip", "xsel"] {
        let args: &[&str] = match cmd {
            "xclip" => &["-selection", "clipboard"],
            "xsel" => &["--clipboard", "--input"],
            _ => &[],
        };
        if let Ok(mut p) = std::process::Command::new(cmd)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(mut s) = p.stdin.take() {
                if s.write_all(val).is_ok() {
                    drop(s);
                    let _ = p.wait();
                    return Ok(());
                }
            }
        }
    }
    Err("no clipboard tool found (wl-copy/xclip/xsel)".into())
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
        Cmd::Devices => cmd_devices(&dir),
        Cmd::Recovery { sub } => match sub {
            RecoveryCmd::Rotate => cmd_recovery_rotate(&dir, rec),
        },
        Cmd::Gen { len, passphrase, no_symbols, copy } => {
            cmd_gen(*len, *passphrase, *no_symbols, *copy)
        }
        Cmd::Clipclear => cmd_clipclear(),
    };
    if let Err(e) = res {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
