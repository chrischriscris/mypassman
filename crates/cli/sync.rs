//! syncd client (DESIGN.md §8 / M3): push/pull ciphertext over HTTPS to a
//! zero-knowledge relay. Ops move as raw signed frames, so `sync` itself
//! never needs the vault unlocked — the server only ever stores what it
//! could verify: owner-signed manifest + device-signed op frames.
//!
//! Credentials live in <data>/mypassman/sync/<vault_id>.conf (0600, the
//! same posture as device signing keys — a write token is strictly less
//! sensitive than the key it complements). Between `pair join` and
//! `pair finish` the file holds the invite code instead of tokens.

use mpm_core::{Manifest, Op};
use mpm_crypto::keys::DeviceKey;
use serde_json::Value;
use sha2::Digest;
use std::io::Write;
use std::path::{Path, PathBuf};

// ── config file ─────────────────────────────────────────────────────

/// Line format `key=value`; keys: url, admin, read, write, invite.
#[derive(Default)]
pub struct SyncCfg {
    pub url: String,
    pub admin: Option<String>,
    pub read: Option<String>,
    pub write: Option<String>,
    pub invite: Option<String>,
}

fn cfg_path(vault_id: &[u8; 16]) -> Result<PathBuf, String> {
    // MPM_DATA mirrors the device-key store override — two devices of one
    // vault on one machine keep separate credentials.
    if let Some(d) = std::env::var_os("MPM_DATA") {
        return Ok(PathBuf::from(d)
            .join("sync")
            .join(format!("{}.conf", mpm_store::hex(vault_id))));
    }
    Ok(dirs::data_local_dir()
        .ok_or("no data dir")?
        .join("mypassman")
        .join("sync")
        .join(format!("{}.conf", mpm_store::hex(vault_id))))
}

fn load_cfg(vault_id: &[u8; 16]) -> Result<Option<SyncCfg>, String> {
    let path = cfg_path(vault_id)?;
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let mut cfg = SyncCfg::default();
    for line in raw.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k.trim() {
            "url" => cfg.url = v.trim().trim_end_matches('/').to_string(),
            "admin" => cfg.admin = Some(v.trim().to_string()),
            "read" => cfg.read = Some(v.trim().to_string()),
            "write" => cfg.write = Some(v.trim().to_string()),
            "invite" => cfg.invite = Some(v.trim().to_string()),
            _ => {}
        }
    }
    if cfg.url.is_empty() {
        return Err(format!("{}: missing url", path.display()));
    }
    Ok(Some(cfg))
}

fn save_cfg(vault_id: &[u8; 16], cfg: &SyncCfg) -> Result<(), String> {
    let path = cfg_path(vault_id)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
    }
    let mut buf = format!("url={}\n", cfg.url);
    for (k, v) in [
        ("admin", &cfg.admin),
        ("read", &cfg.read),
        ("write", &cfg.write),
        ("invite", &cfg.invite),
    ] {
        if let Some(v) = v {
            buf.push_str(&format!("{k}={v}\n"));
        }
    }
    // 0600 at creation — a token must never exist at 0644, even briefly
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| e.to_string())?;
        f.write_all(buf.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, buf).map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ── http ────────────────────────────────────────────────────────────

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(20)))
        .build()
        .into()
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn http(
    method: &str,
    url: &str,
    token: Option<&str>,
    body: Option<&[u8]>,
    extra: &[(&str, &str)],
) -> Result<Resp, String> {
    let agent = agent();
    let auth = token.map(|t| format!("Bearer {t}"));
    let has_ct = extra
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
    let res = if method == "GET" {
        let mut rb = agent.get(url);
        if let Some(t) = &auth {
            rb = rb.header("Authorization", t);
        }
        for (k, v) in extra {
            rb = rb.header(*k, *v);
        }
        rb.call()
    } else {
        let mut rb = match method {
            "POST" => agent.post(url),
            "PUT" => agent.put(url),
            _ => return Err(format!("bad method {method}")),
        };
        if let Some(t) = &auth {
            rb = rb.header("Authorization", t);
        }
        if body.is_some() && !has_ct {
            rb = rb.header("content-type", "application/octet-stream");
        }
        for (k, v) in extra {
            rb = rb.header(*k, *v);
        }
        match body {
            Some(b) => rb.send(b),
            None => rb.send_empty(),
        }
    }
    .map_err(|e| format!("{method} {url}: {e}"))?;
    let status = res.status().as_u16();
    let headers = res
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let body = res
        .into_body()
        .read_to_vec()
        .map_err(|e| format!("{method} {url}: {e}"))?;
    Ok(Resp {
        status,
        headers,
        body,
    })
}

fn api(cfg: &SyncCfg, vault_id: &[u8; 16], sub: &str) -> String {
    format!("{}/v/{}/{}", cfg.url, mpm_store::hex(vault_id), sub)
}

fn json(body: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(body).map_err(|e| format!("bad server json: {e}"))
}

fn jstr(v: &Value, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("server response missing '{key}'"))
}

fn jnum(v: &Value, key: &str) -> Result<u64, String> {
    v.get(key)
        .and_then(|x| x.as_u64())
        .ok_or_else(|| format!("server response missing '{key}'"))
}

/// Surface the server's error string when it gave us one.
fn check(status: u16, body: &[u8]) -> Result<(), String> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    let msg = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("error")?.as_str().map(str::to_string))
        .unwrap_or_else(|| {
            String::from_utf8_lossy(body)
                .trim()
                .chars()
                .take(120)
                .collect()
        });
    Err(format!("server {status}: {msg}"))
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("bad hex".into());
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect())
}

fn unhex16(s: &str) -> Result<[u8; 16], String> {
    unhex(s)?
        .try_into()
        .map_err(|_| "bad device id".to_string())
}

fn unhex32(s: &str) -> Result<[u8; 32], String> {
    unhex(s)?.try_into().map_err(|_| "bad vk".to_string())
}

fn sha256_hex(b: &[u8]) -> String {
    mpm_store::hex(&sha2::Sha256::digest(b))
}

/// Token for a scope: the scoped token if present, else admin.
fn tok<'a>(cfg: &'a SyncCfg, scoped: &'a Option<String>, what: &str) -> Result<&'a str, String> {
    scoped
        .as_deref()
        .or(cfg.admin.as_deref())
        .ok_or_else(|| format!("no {what} credential — run `mypassman sync init` or re-pair"))
}

// ── commands ────────────────────────────────────────────────────────

/// `mypassman sync init <url> --setup-key <k>` — first device bootstraps
/// the vault onto a fresh syncd deployment; stores admin + device-bound
/// read/write tokens.
pub fn cmd_sync_init(dir: &Path, url: &str, setup_key: &str) -> Result<(), String> {
    let m = mpm_store::load_manifest(dir).map_err(|e| e.to_string())?;
    let raw = std::fs::read(dir.join(mpm_store::MANIFEST)).map_err(|e| e.to_string())?;
    let dev = mpm_store::load_device_key(&m.vault_id).map_err(|e| e.to_string())?;
    if load_cfg(&m.vault_id)?.is_some() {
        return Err("already configured — edit the .conf or delete it to re-init".into());
    }
    let url = url.trim_end_matches('/');
    let r = http(
        "POST",
        &format!("{url}/v/{}/bootstrap", mpm_store::hex(&m.vault_id)),
        None,
        Some(&raw),
        &[("x-setup-key", setup_key)],
    )?;
    check(r.status, &r.body)?;
    let admin = jstr(&json(&r.body)?, "token")?;

    // device-bound scoped tokens for daily use; admin stays for pair/revoke
    let dev_hex = mpm_store::hex(&dev.id);
    let mint = |scope: &str| -> Result<String, String> {
        let r = http(
            "POST",
            &format!("{url}/v/{}/tokens", mpm_store::hex(&m.vault_id)),
            Some(&admin),
            Some(
                serde_json::json!({"scope": scope, "device": dev_hex})
                    .to_string()
                    .as_bytes(),
            ),
            &[("content-type", "application/json")],
        )?;
        check(r.status, &r.body)?;
        jstr(&json(&r.body)?, "token")
    };
    let read = mint("read")?;
    let write = mint("write")?;

    save_cfg(
        &m.vault_id,
        &SyncCfg {
            url: url.into(),
            admin: Some(admin),
            read: Some(read),
            write: Some(write),
            invite: None,
        },
    )?;
    eprintln!("sync configured → {url}");
    eprintln!("vault {}", mpm_store::hex(&m.vault_id));
    eprintln!("run `mypassman sync` to push/pull; `mypassman pair invite` to add a device");
    Ok(())
}

/// `mypassman sync` — pull foreign logs, push our own, reconcile the
/// manifest. No unlock: everything crossing the wire is ciphertext.
pub fn cmd_sync(dir: &Path) -> Result<(), String> {
    let m = mpm_store::load_manifest(dir).map_err(|e| e.to_string())?;
    let cfg = load_cfg(&m.vault_id)?.ok_or(
        "no sync config — `mypassman sync init <url>` on the first device, \
         `mypassman pair join <url> <code>` on a new one",
    )?;
    let me = mpm_store::load_device_key(&m.vault_id)
        .map_err(|e| e.to_string())?
        .id;
    let rtok = tok(&cfg, &cfg.read, "read")?.to_string();
    let wtok = tok(&cfg, &cfg.write, "write")?.to_string();

    // remote state
    let r = http(
        "GET",
        &api(&cfg, &m.vault_id, "state"),
        Some(&rtok),
        None,
        &[],
    )?;
    check(r.status, &r.body)?;
    let state = json(&r.body)?;
    let heads: Vec<(String, u64)> = state
        .get("heads")
        .and_then(|h| h.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|h| Some((jstr(h, "device").ok()?, jnum(h, "head").ok()?)))
        .collect();

    // ── pull foreign logs (raw frames → append verbatim) ──
    let mut pulled = 0u64;
    for (dev_hex, head) in &heads {
        let dev = unhex16(dev_hex)?;
        if dev == me {
            continue;
        }
        let lr = mpm_store::read_ops(dir, &dev).map_err(|e| e.to_string())?;
        if lr.torn_tail {
            eprintln!("warning: foreign log {dev_hex} has a torn tail — not appending past it");
            continue;
        }
        let mut count = lr.ops.len() as u64;
        while count < *head {
            let r = http(
                "GET",
                &api(
                    &cfg,
                    &m.vault_id,
                    &format!("ops?device={dev_hex}&since={count}&limit=256"),
                ),
                Some(&rtok),
                None,
                &[],
            )?;
            check(r.status, &r.body)?;
            if r.body.is_empty() {
                break;
            }
            // server emits whole frames only; a partial tail means
            // corruption — refuse rather than plant a torn log
            let n = count_frames(&r.body)?;
            append_frames(dir, &dev, &r.body)?;
            pulled += n as u64;
            count += n as u64;
            let more = r
                .headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("x-more") && v == "1");
            if !more {
                break;
            }
        }
        if count < *head {
            eprintln!("warning: pulled {dev_hex} to seq {count} but remote head is {head}");
        }
    }

    // ── push our own ops ──
    let own = mpm_store::read_ops(dir, &me).map_err(|e| e.to_string())?;
    let remote_head = heads
        .iter()
        .find(|(d, _)| unhex16(d).ok() == Some(me))
        .map(|(_, h)| *h)
        .unwrap_or(0);
    let mut pushed = 0u64;
    if (own.ops.len() as u64) < remote_head {
        eprintln!(
            "warning: server holds {} of our ops but local log has {} — \
             this device lost state (restored backup?). Re-pair if unintended.",
            remote_head,
            own.ops.len()
        );
    } else if own.ops.len() as u64 > remote_head {
        let mut body = Vec::new();
        for op in &own.ops[remote_head as usize..] {
            body.extend_from_slice(&op.encode());
        }
        let r = http(
            "POST",
            &api(
                &cfg,
                &m.vault_id,
                &format!("ops?device={}", mpm_store::hex(&me)),
            ),
            Some(&wtok),
            Some(&body),
            &[],
        )?;
        check(r.status, &r.body)?;
        pushed = own.ops.len() as u64 - remote_head;
    }

    // ── manifest reconcile ──
    let r = http(
        "GET",
        &api(&cfg, &m.vault_id, "manifest"),
        Some(&rtok),
        None,
        &[],
    )?;
    check(r.status, &r.body)?;
    let rv = json(&r.body)?;
    let remote_bytes = unhex(&jstr(&rv, "manifest")?)?;
    let remote_m = Manifest::from_file(&remote_bytes).map_err(|e| e.to_string())?;
    if remote_m.vault_id != m.vault_id {
        return Err("server manifest vault_id mismatch — wrong vault?".into());
    }
    let local_bytes = std::fs::read(dir.join(mpm_store::MANIFEST)).map_err(|e| e.to_string())?;
    let mut manifest_note = "unchanged".to_string();
    if remote_bytes != local_bytes {
        let remote_wins = if remote_m.snapshot_epoch > m.snapshot_epoch {
            true
        } else if m.snapshot_epoch > remote_m.snapshot_epoch {
            false
        } else {
            // same epochs, bytes differ → registry changed. More devices =
            // the newer view in practice; equal counts → prefer the server.
            remote_m.devices.len() >= m.devices.len()
        };
        if remote_wins {
            mpm_store::write_manifest(dir, &remote_bytes).map_err(|e| e.to_string())?;
            manifest_note = format!("adopted remote (epoch {})", remote_m.snapshot_epoch);
        } else if let Some(admin) = &cfg.admin {
            let r = http(
                "PUT",
                &api(&cfg, &m.vault_id, "manifest"),
                Some(admin),
                Some(
                    serde_json::json!({
                        "manifest": mpm_store::hex(&local_bytes),
                        "base_hash": sha256_hex(&remote_bytes),
                    })
                    .to_string()
                    .as_bytes(),
                ),
                &[("content-type", "application/json")],
            )?;
            match check(r.status, &r.body) {
                Ok(()) => manifest_note = "pushed local".into(),
                Err(e) if r.status == 409 => {
                    manifest_note = format!("push raced ({e}) — rerun sync");
                }
                Err(e) => return Err(e),
            }
        } else {
            manifest_note = "local manifest ahead but no admin credential — pushed nothing".into();
        }
    }

    eprintln!("synced: pulled {pulled} op(s), pushed {pushed}, manifest {manifest_note}");
    Ok(())
}

/// Count complete op frames; error on a partial tail — the server must
/// only ever send whole frames.
fn count_frames(buf: &[u8]) -> Result<usize, String> {
    let (mut pos, mut n) = (0usize, 0usize);
    while pos < buf.len() {
        let (_, end) = Op::decode(&buf[pos..]).map_err(|e| e.to_string())?;
        pos += end;
        n += 1;
    }
    Ok(n)
}

/// Append already-encoded frames to a foreign log (append_op() takes a
/// decoded Op; pulled frames arrive pre-encoded).
fn append_frames(dir: &Path, device: &[u8; 16], frames: &[u8]) -> Result<(), String> {
    let path = mpm_store::log_path(dir, device);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    if !f.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("op log is not a regular file".into());
    }
    f.write_all(frames).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    Ok(())
}

// ── pairing ─────────────────────────────────────────────────────────

/// `mypassman pair invite` — owner mints a short-lived enrollment code.
pub fn cmd_pair_invite(dir: &Path, qr: bool) -> Result<(), String> {
    let m = mpm_store::load_manifest(dir).map_err(|e| e.to_string())?;
    let cfg = load_cfg(&m.vault_id)?.ok_or("no sync config — run `mypassman sync init`")?;
    let admin = cfg
        .admin
        .as_deref()
        .ok_or("no admin credential on this device")?;
    let r = http(
        "POST",
        &api(&cfg, &m.vault_id, "enroll/invite"),
        Some(admin),
        None,
        &[],
    )?;
    check(r.status, &r.body)?;
    let v = json(&r.body)?;
    // invite = vault_id.code — the code alone can't route (the vault_id
    // selects which Durable Object holds it)
    let invite = format!("{}.{}", mpm_store::hex(&m.vault_id), jstr(&v, "code")?);
    println!("{invite}");
    if qr {
        // deep link for phone apps: mpm://pair?server=<url>&invite=<v>.<c>
        let link = format!(
            "mpm://pair?server={}&invite={}",
            pct_encode(&cfg.url),
            invite
        );
        let code = qrcode::QrCode::new(link.as_bytes()).map_err(|e| format!("qr: {e}"))?;
        eprintln!(
            "{}",
            code.render::<qrcode::render::unicode::Dense1x2>()
                .quiet_zone(true)
                .build()
        );
    }
    eprintln!(
        "valid {}s — on the new device: `mypassman pair join {} <invite>`",
        jnum(&v, "ttl_s")?,
        cfg.url
    );
    Ok(())
}

/// Minimal percent-encoding for the server URL inside the mpm:// link.
fn pct_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// `mypassman pair pending` — list devices waiting for approval.
pub fn cmd_pair_pending(dir: &Path) -> Result<(), String> {
    let m = mpm_store::load_manifest(dir).map_err(|e| e.to_string())?;
    let cfg = load_cfg(&m.vault_id)?.ok_or("no sync config")?;
    let admin = cfg
        .admin
        .as_deref()
        .ok_or("no admin credential on this device")?;
    let r = http(
        "GET",
        &api(&cfg, &m.vault_id, "enroll/pending"),
        Some(admin),
        None,
        &[],
    )?;
    check(r.status, &r.body)?;
    let v = json(&r.body)?;
    let rows = v.as_array().cloned().unwrap_or_default();
    if rows.is_empty() {
        println!("no pending devices");
        return Ok(());
    }
    println!("{:<34} {:<24} CREATED", "DEVICE", "NAME");
    for p in &rows {
        println!(
            "{:<34} {:<24} {}",
            jstr(p, "device")?,
            jstr(p, "name")?,
            jnum(p, "created")?
        );
    }
    Ok(())
}

/// `mypassman pair approve <device-prefix>` — the signature act: add the
/// device to the owner-signed manifest and push it. The server grants
/// tokens only once the new device appears there.
pub fn cmd_pair_approve(dir: &Path, rec: bool, prefix: &str) -> Result<(), String> {
    let m = mpm_store::load_manifest(dir).map_err(|e| e.to_string())?;
    let cfg = load_cfg(&m.vault_id)?.ok_or("no sync config")?;
    let admin = cfg
        .admin
        .as_deref()
        .ok_or("no admin credential on this device")?
        .to_string();
    let r = http(
        "GET",
        &api(&cfg, &m.vault_id, "enroll/pending"),
        Some(&admin),
        None,
        &[],
    )?;
    check(r.status, &r.body)?;
    let pending = json(&r.body)?.as_array().cloned().unwrap_or_default();
    let matches: Vec<_> = pending
        .iter()
        .filter(|p| {
            p.get("device")
                .and_then(|d| d.as_str())
                .map(|d| d.starts_with(prefix))
                .unwrap_or(false)
        })
        .collect();
    let p = match matches.len() {
        0 => return Err(format!("no pending device matching '{prefix}'")),
        1 => matches[0],
        _ => return Err(format!("'{prefix}' is ambiguous — more characters")),
    };
    let dev_id = unhex16(&jstr(p, "device")?)?;
    let dev_vk = unhex32(&jstr(p, "vk")?)?;
    let dev_name = jstr(p, "name")?;

    // owner-signed manifest update — this IS the approval
    let mut vault = crate::unlock(dir, rec)?;
    vault.manifest.devices.push(mpm_core::DeviceEntry {
        id: dev_id,
        vk: dev_vk,
        name: dev_name.clone(),
        active: true,
        enrolled_at: mpm_core::vault::now_hlc(),
        extra: Vec::new(),
    });
    let bytes = vault.manifest.to_file(&vault.bundle().owner_signing_key());
    mpm_store::write_manifest(dir, &bytes).map_err(|e| e.to_string())?;

    // push CAS on the remote manifest we just read
    let r = http(
        "GET",
        &api(&cfg, &m.vault_id, "manifest"),
        Some(&admin),
        None,
        &[],
    )?;
    check(r.status, &r.body)?;
    let remote_bytes = unhex(&jstr(&json(&r.body)?, "manifest")?)?;
    let r = http(
        "PUT",
        &api(&cfg, &m.vault_id, "manifest"),
        Some(&admin),
        Some(
            serde_json::json!({
                "manifest": mpm_store::hex(&bytes),
                "base_hash": sha256_hex(&remote_bytes),
            })
            .to_string()
            .as_bytes(),
        ),
        &[("content-type", "application/json")],
    )?;
    check(r.status, &r.body)?;
    eprintln!(
        "approved '{dev_name}' ({}) — run `mypassman pair finish` on that device",
        mpm_store::hex(&dev_id)
    );
    Ok(())
}

/// `mypassman pair decline <device-prefix>` — drop a pending request.
pub fn cmd_pair_decline(dir: &Path, prefix: &str) -> Result<(), String> {
    let m = mpm_store::load_manifest(dir).map_err(|e| e.to_string())?;
    let cfg = load_cfg(&m.vault_id)?.ok_or("no sync config")?;
    let admin = cfg
        .admin
        .as_deref()
        .ok_or("no admin credential on this device")?;
    let r = http(
        "GET",
        &api(&cfg, &m.vault_id, "enroll/pending"),
        Some(admin),
        None,
        &[],
    )?;
    check(r.status, &r.body)?;
    let pending = json(&r.body)?.as_array().cloned().unwrap_or_default();
    let matches: Vec<_> = pending
        .iter()
        .filter_map(|p| p.get("device").and_then(|d| d.as_str()))
        .filter(|d| d.starts_with(prefix))
        .collect();
    let dev = match matches.len() {
        0 => return Err(format!("no pending device matching '{prefix}'")),
        1 => matches[0],
        _ => return Err(format!("'{prefix}' is ambiguous — more characters")),
    };
    let r = http(
        "POST",
        &api(&cfg, &m.vault_id, "enroll/decline"),
        Some(admin),
        Some(serde_json::json!({"device": dev}).to_string().as_bytes()),
        &[("content-type", "application/json")],
    )?;
    check(r.status, &r.body)?;
    eprintln!("declined {dev}");
    Ok(())
}

/// `mypassman pair join <url> <invite>` — NEW device side. The invite is
/// `<vault_id>.<code>` (printed by `pair invite`): the code alone can't
/// route — the vault_id selects which Durable Object holds it.
///
/// Generates the device key, submits the public key under the invite,
/// writes the pulled manifest, and confirms the master password against
/// the password slot + owner_vk anchor. We DON'T call unlock(): the
/// device isn't in the registry yet, so Vault::new would NotEnrolled —
/// approval is what `pair finish` waits for.
pub fn cmd_pair_join(dir: &Path, url: &str, invite: &str, name: &str) -> Result<(), String> {
    if dir.join(mpm_store::MANIFEST).exists() {
        return Err("vault already exists here — pair join is for a fresh directory".into());
    }
    let Some((vault_hex, code)) = invite.split_once('.') else {
        return Err("invite should look like <vault_id>.<code>".into());
    };
    let vault_id = unhex16(vault_hex)?;
    let dev = DeviceKey::generate();
    let url = url.trim_end_matches('/');
    let base = format!("{url}/v/{vault_hex}");

    let r = http(
        "POST",
        &format!("{base}/enroll/join"),
        Some(code),
        Some(
            serde_json::json!({
                "device": mpm_store::hex(&dev.id),
                "vk": mpm_store::hex(&dev.verifying_key()),
                "name": name,
            })
            .to_string()
            .as_bytes(),
        ),
        &[("content-type", "application/json")],
    )?;
    check(r.status, &r.body)?;
    let manifest_bytes = unhex(&jstr(&json(&r.body)?, "manifest")?)?;
    let m = Manifest::from_file(&manifest_bytes).map_err(|e| e.to_string())?;
    if m.vault_id != vault_id {
        return Err("server returned a manifest for a different vault".into());
    }

    mpm_store::init_dir(dir).map_err(|e| e.to_string())?;
    mpm_store::write_manifest(dir, &manifest_bytes).map_err(|e| e.to_string())?;
    mpm_store::save_device_key(&vault_id, &dev).map_err(|e| e.to_string())?;
    save_cfg(
        &vault_id,
        &SyncCfg {
            url: url.into(),
            invite: Some(code.to_string()),
            ..Default::default()
        },
    )?;

    // prove the password now rather than at finish: unwrap the password
    // slot and anchor owner_vk to the bundle it yields. The device itself
    // stays unenrolled until the owner approves.
    let pw = crate::read_password("master password: ");
    let mut ok = false;
    for slot in &m.wrap_slots {
        if slot.slot_type != mpm_core::manifest::SLOT_PASSWORD {
            continue;
        }
        let Some((params, salt)) = &slot.kdf else {
            continue;
        };
        if params.check_bounds(crate::DEVICE_KDF_CAP_KIB).is_err() {
            continue;
        }
        if let Ok(kek) =
            mpm_crypto::kdf::derive_kek(pw.as_bytes(), salt, params).map_err(|e| e.to_string())
        {
            if let Ok(bundle) = mpm_crypto::keys::KeyBundle::unwrap(
                &kek,
                &mpm_core::aad::wrap_slot(&vault_id, m.key_epoch, slot.slot_type),
                &slot.blob,
            ) {
                if bundle.owner_verifying_key() == m.owner_vk {
                    ok = true;
                    break;
                }
            }
        }
    }
    if !ok {
        return Err("master password didn't unwrap this vault — vault written, \
             fix the password before `pair finish`"
            .into());
    }

    eprintln!("requested as '{name}' ({})", mpm_store::hex(&dev.id));
    eprintln!(
        "waiting for the owner: `mypassman pair pending` / `pair approve {}`",
        &mpm_store::hex(&dev.id)[..8]
    );
    eprintln!("then here: `mypassman pair finish`");
    Ok(())
}

/// `mypassman pair finish` — after the owner approves, exchange the invite
/// code for device-bound read/write tokens and pull everything down.
pub fn cmd_pair_finish(dir: &Path) -> Result<(), String> {
    let m = mpm_store::load_manifest(dir).map_err(|e| e.to_string())?;
    let mut cfg =
        load_cfg(&m.vault_id)?.ok_or("no sync config — run `mypassman pair join` first")?;
    let invite = cfg
        .invite
        .clone()
        .ok_or("no pending enrollment — already finished or never joined")?;
    let me = mpm_store::load_device_key(&m.vault_id)
        .map_err(|e| e.to_string())?
        .id;

    let r = http(
        "POST",
        &api(&cfg, &m.vault_id, "enroll/finish"),
        Some(&invite),
        Some(
            serde_json::json!({"device": mpm_store::hex(&me)})
                .to_string()
                .as_bytes(),
        ),
        &[("content-type", "application/json")],
    )?;
    check(r.status, &r.body)?;
    let v = json(&r.body)?;
    cfg.read = Some(jstr(&v, "read")?);
    cfg.write = Some(jstr(&v, "write")?);
    cfg.invite = None;
    let manifest_bytes = unhex(&jstr(&v, "manifest")?)?;
    let rm = Manifest::from_file(&manifest_bytes).map_err(|e| e.to_string())?;
    if rm.vault_id != m.vault_id {
        return Err("server returned a manifest for a different vault".into());
    }
    mpm_store::write_manifest(dir, &manifest_bytes).map_err(|e| e.to_string())?;
    save_cfg(&m.vault_id, &cfg)?;
    eprintln!("paired — pulling ops");
    cmd_sync(dir)?;
    eprintln!("enrollment complete");
    Ok(())
}

/// `mypassman pair revoke <device-prefix>` — the owner marks the device
/// inactive in the manifest (re-signed + pushed with CAS), then the server
/// burns its tokens. Revocation is forward-looking: the device keeps
/// whatever ciphertext it already pulled.
pub fn cmd_pair_revoke(dir: &Path, rec: bool, prefix: &str) -> Result<(), String> {
    let m = mpm_store::load_manifest(dir).map_err(|e| e.to_string())?;
    let cfg = load_cfg(&m.vault_id)?.ok_or("no sync config")?;
    let admin = cfg
        .admin
        .as_deref()
        .ok_or("no admin credential on this device")?
        .to_string();
    let me = mpm_store::load_device_key(&m.vault_id)
        .map(|d| d.id)
        .map_err(|_| "no device key — is this vault unlocked here?".to_string())?;

    let matches: Vec<_> = m
        .devices
        .iter()
        .filter(|d| mpm_store::hex(&d.id).starts_with(prefix))
        .collect();
    let dev = match matches.len() {
        0 => return Err(format!("no device matching '{prefix}'")),
        1 => matches[0],
        _ => return Err(format!("'{prefix}' is ambiguous — more characters")),
    };
    if dev.id == me {
        return Err("refusing to revoke this device — run it from another enrolled device".into());
    }
    if !dev.active {
        return Err(format!("'{}' is already revoked", dev.name));
    }
    let dev_hex = mpm_store::hex(&dev.id);
    let dev_name = dev.name.clone();

    // owner-signed manifest update — revoke IS a signature, not a flag
    let mut vault = crate::unlock(dir, rec)?;
    for d in &mut vault.manifest.devices {
        if mpm_store::hex(&d.id) == dev_hex {
            d.active = false;
        }
    }
    let bytes = vault.manifest.to_file(&vault.bundle().owner_signing_key());
    mpm_store::write_manifest(dir, &bytes).map_err(|e| e.to_string())?;

    // CAS-push the manifest, then burn the device's tokens server-side
    let r = http(
        "GET",
        &api(&cfg, &m.vault_id, "manifest"),
        Some(&admin),
        None,
        &[],
    )?;
    check(r.status, &r.body)?;
    let remote_bytes = unhex(&jstr(&json(&r.body)?, "manifest")?)?;
    let r = http(
        "PUT",
        &api(&cfg, &m.vault_id, "manifest"),
        Some(&admin),
        Some(
            serde_json::json!({
                "manifest": mpm_store::hex(&bytes),
                "base_hash": sha256_hex(&remote_bytes),
            })
            .to_string()
            .as_bytes(),
        ),
        &[("content-type", "application/json")],
    )?;
    check(r.status, &r.body)?;
    let r = http(
        "POST",
        &api(&cfg, &m.vault_id, "revoke"),
        Some(&admin),
        Some(
            serde_json::json!({"device": dev_hex})
                .to_string()
                .as_bytes(),
        ),
        &[("content-type", "application/json")],
    )?;
    check(r.status, &r.body)?;
    eprintln!("revoked '{dev_name}' ({dev_hex})");
    eprintln!("note: it keeps whatever it already synced — rotate exposed secrets if needed");
    Ok(())
}
