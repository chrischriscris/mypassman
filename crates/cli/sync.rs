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
    check_url_scheme(&cfg.url)?;
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
    // Atomic write — tmp+rename. A crash mid-truncate would leave an empty
    // conf; in `pair finish` the invite is already burned by then, so the
    // tokens would be unrecoverable.
    let tmp = path.with_extension("tmp");
    // 0600 at creation — a token must never exist at 0644, even briefly
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        f.write_all(buf.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp, &buf).map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    // fsync the directory too — the rename itself must be durable, or a
    // crash after `pair finish` loses tokens whose invite is already burned
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        std::fs::File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Sync endpoints carry bearer tokens — refuse cleartext HTTP except to
/// loopback (dev servers) or when MPM_SYNC_INSECURE=1 is set explicitly.
fn check_url_scheme(url: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let host = rest
            .split(['/', ':'])
            .next()
            .unwrap_or("")
            .trim_matches(|c| c == '[' || c == ']');
        let loopback = host == "localhost"
            || host == "::1"
            || host.strip_prefix("127.").is_some_and(|t| {
                t.split('.').all(|o| o.parse::<u8>().is_ok()) && t.split('.').count() == 3
            });
        if loopback || std::env::var("MPM_SYNC_INSECURE").as_deref() == Ok("1") {
            return Ok(());
        }
        return Err(format!(
            "refusing plain-http sync endpoint {url:?} — bearer tokens would travel \
             cleartext. Use https:// (or MPM_SYNC_INSECURE=1 for a trusted LAN)"
        ));
    }
    Err(format!(
        "sync url {url:?} must start with https:// or http://"
    ))
}

/// Max bytes any single response may occupy — 64 MiB. The wire protocol
/// is small (pages of ≤256 frames, a ≤64KiB manifest); this only guards
/// against a malicious/buggy server streaming garbage.
const MAX_RESP_BYTES: u64 = 64 << 20;

// ── push batching ───────────────────────────────────────────────────

/// Relay ingest caps (SYNC.md): one POST may carry at most 256 frames and
/// at most 1 MiB of body. Both caps bind — a frame count alone still lets
/// large ops overflow the body limit.
const PUSH_MAX_FRAMES: usize = 256;
const PUSH_MAX_BYTES: usize = 1 << 20;

/// Split `ops` (ascending seqs, all ahead of the remote head) into index
/// ranges that each fit inside BOTH push caps. A single frame larger than
/// the body cap can never be accepted — fail it loudly instead of
/// retrying forever.
fn push_batch_bounds(ops: &[&Op]) -> Result<Vec<(usize, usize)>, String> {
    let mut out = Vec::new();
    let (mut start, mut n, mut bytes) = (0usize, 0usize, 0usize);
    for (i, op) in ops.iter().enumerate() {
        let flen = mpm_core::op::OP_HEADER_LEN + op.ct.len();
        if flen > PUSH_MAX_BYTES {
            return Err(format!(
                "op seq {} is {} bytes on the wire — exceeds the relay's 1 MiB cap and can never sync",
                op.seq, flen
            ));
        }
        if n == PUSH_MAX_FRAMES || bytes + flen > PUSH_MAX_BYTES {
            out.push((start, i));
            start = i;
            n = 0;
            bytes = 0;
        }
        n += 1;
        bytes += flen;
    }
    if n > 0 {
        out.push((start, ops.len()));
    }
    Ok(out)
}

// ── http ────────────────────────────────────────────────────────────

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(20)))
        // a fixed API never legitimately redirects — refusing them also
        // means a compromised server can't bounce tokens/frames sideways
        .max_redirects(0)
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
    // A hostile or broken server must not be able to OOM us: bound the
    // body. Ops pages are server-capped at 256 frames; a page is far
    // under this — the cap exists for the pathological case only.
    let mut body = res.into_body();
    let body = body
        .with_config()
        .limit(MAX_RESP_BYTES)
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
pub fn cmd_sync_init(dir: &Path, url: &str, setup_key: Option<&str>) -> Result<(), String> {
    // argv → $MPM_SETUP_KEY → prompt: argv lands in shell history/`ps`
    let owned;
    let setup_key = match setup_key {
        Some(k) => k,
        None => {
            owned = std::env::var("MPM_SETUP_KEY")
                .inspect(|_| std::env::remove_var("MPM_SETUP_KEY"))
                .unwrap_or_else(|_| crate::read_line("setup key"));
            owned.as_str()
        }
    };
    let m = mpm_store::load_manifest(dir).map_err(|e| e.to_string())?;
    let raw = std::fs::read(dir.join(mpm_store::MANIFEST)).map_err(|e| e.to_string())?;
    let dev = mpm_store::load_device_key(&m.vault_id).map_err(|e| e.to_string())?;
    if load_cfg(&m.vault_id)?.is_some() {
        return Err("already configured — edit the .conf or delete it to re-init".into());
    }
    check_url_scheme(url)?;
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
    // Serialize sync runs per vault (daemon's timer vs. a manual `sync`):
    // without it two pull loops read the same "new" foreign frames and
    // each appends them — a duplicated seq breaks the log's continuity.
    // Deliberately NOT the vault .lock: that one must stay free of
    // network I/O so the daemon can keep answering requests mid-sync.
    let _sync_lock = sync_lock(&m.vault_id)?;
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
    if r.status == 401 || r.status == 403 {
        // the device's tokens are burned — most likely a revocation this
        // device can't learn about any other way
        return Err(format!(
            "{} — this device may have been revoked (`pair approve`/`revoke` happen owner-side)",
            check(r.status, &r.body).unwrap_err()
        ));
    }
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

    // adopted compaction base (device → covered seq) — pull cursors start
    // past it so dropped prefixes never re-download
    let bases = mpm_store::load_base_vector(dir).map_err(|e| e.to_string())?;

    // ── pull foreign logs (raw frames → verify → append verbatim) ──
    let mut pulled = 0u64;
    for (dev_hex, head) in &heads {
        let dev = unhex16(dev_hex)?;
        if dev == me {
            continue;
        }
        // Verify against the LOCAL manifest registry: an unknown device
        // (e.g. enrolled elsewhere, remote manifest not yet adopted) is
        // skipped — its ops can never merge anyway. A revoked device is
        // still pulled UP TO its revocation horizon: ops it wrote while
        // trusted belong in every replica. The manifest reconcile below
        // catches us up for the next sync.
        let Some(entry) = m.device(&dev) else {
            eprintln!("note: skipping {dev_hex} — not in local device registry");
            continue;
        };
        let horizon = if entry.active {
            u64::MAX
        } else {
            match entry.revoked_seq {
                Some(h) => h,
                None => {
                    eprintln!("note: skipping {dev_hex} — device is revoked");
                    continue;
                }
            }
        };
        let head = (*head).min(horizon);
        if head == 0 {
            continue;
        }
        let lr = mpm_store::read_ops(dir, &dev).map_err(|e| e.to_string())?;
        // pull cursor by SEQ, not position: compacted logs start mid-chain.
        // An empty log still has a cursor — the adopted base vector's
        // covered seq — so covered ops never re-pull.
        let base = bases
            .iter()
            .find(|(d, _)| d == &dev)
            .map(|(_, s)| *s)
            .unwrap_or(0);
        let mut count = lr.ops.last().map(|o| o.seq).unwrap_or(base).max(base);
        if count > horizon {
            // Pulled while the device was still trusted, but now past its
            // revocation horizon — these bytes are untrusted; drop them so
            // they stop tripping verification at every unlock.
            let keep: u64 = lr
                .ops
                .iter()
                .take_while(|o| o.seq <= horizon)
                .map(|o| o.encode().len() as u64)
                .sum();
            eprintln!("note: dropping post-revocation tail of {dev_hex} (past seq {horizon})");
            mpm_store::truncate_log(dir, &dev, keep).map_err(|e| e.to_string())?;
            count = lr
                .ops
                .iter()
                .take_while(|o| o.seq <= horizon)
                .last()
                .map(|o| o.seq)
                .unwrap_or(base)
                .max(base);
        }
        if lr.torn_tail {
            // Heal it: the tail bytes never decoded, so they are by
            // definition unverified — truncate to the verified prefix and
            // pull the rest fresh from the relay.
            let keep: u64 = lr.ops.iter().map(|o| o.encode().len() as u64).sum();
            eprintln!("note: truncating torn tail of foreign log {dev_hex} — will re-pull");
            mpm_store::truncate_log(dir, &dev, keep).map_err(|e| e.to_string())?;
        }
        while count < head {
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
            // Server emits whole frames only; verify seq continuity and
            // each device signature BEFORE the bytes touch the log — a
            // hostile relay could otherwise poison it with data that only
            // fails at unlock. Fail closed: a bad frame aborts the sync.
            let (n, nbytes) = verify_frames(&r.body, &dev, count + 1, &entry.vk, horizon)?;
            if nbytes > 0 {
                // append only the verified prefix — the page may carry
                // post-horizon frames we must never persist
                mpm_store::append_frames(dir, &dev, &r.body[..nbytes])
                    .map_err(|e| e.to_string())?;
                pulled += n as u64;
                count += n as u64;
            }
            let more = r
                .headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("x-more") && v == "1");
            if n == 0 || !more {
                break;
            }
        }
        if count < head {
            eprintln!("warning: pulled {dev_hex} to seq {count} but head is {head}");
        }
    }

    // ── push our own ops ──
    let own = mpm_store::read_ops(dir, &me).map_err(|e| e.to_string())?;
    let own_base = bases
        .iter()
        .find(|(d, _)| d == &me)
        .map(|(_, s)| *s)
        .unwrap_or(0);
    let own_tip = own.ops.last().map(|o| o.seq).unwrap_or(own_base);
    let remote_head = heads
        .iter()
        .find(|(d, _)| unhex16(d).ok() == Some(me))
        .map(|(_, h)| *h)
        .unwrap_or(0);
    let mut pushed = 0u64;
    if remote_head > own_tip {
        eprintln!(
            "warning: server holds {} of our ops but local log has {} — \
             this device lost state (restored backup?). Re-pair if unintended.",
            remote_head, own_tip
        );
    } else if remote_head < own_base {
        eprintln!(
            "warning: relay is missing ops our checkpoint already covered — \
             another replica's full log must re-push them"
        );
    }
    if own_tip > remote_head {
        let pending: Vec<&Op> = own.ops.iter().filter(|o| o.seq > remote_head).collect();
        for (s, e) in push_batch_bounds(&pending)? {
            let mut body = Vec::new();
            for op in &pending[s..e] {
                body.extend_from_slice(&op.encode());
            }
            let batch_last = pending[e - 1].seq;
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
            // the relay must report a head covering every frame we sent —
            // anything less means it accepted a prefix it can't name
            let head = jnum(&json(&r.body)?, "head")?;
            if head < batch_last {
                return Err(format!(
                    "relay accepted a push batch but reports head {head} < {batch_last} — rerun sync"
                ));
            }
            pushed = batch_last - remote_head;
        }
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
        // Pin the trust anchors before ANY adoption: owner_vk never
        // rotates, key_epoch only moves forward. A replayed or forged
        // manifest fails here instead of bricking the local copy.
        if remote_m.owner_vk != m.owner_vk {
            return Err("refusing remote manifest: owner key changed".into());
        }
        if remote_m.key_epoch < m.key_epoch {
            return Err("refusing remote manifest: key_epoch regressed".into());
        }
        use std::cmp::Ordering;
        match remote_m.snapshot_epoch.cmp(&m.snapshot_epoch) {
            Ordering::Greater => {
                mpm_store::write_manifest(dir, &remote_bytes).map_err(|e| e.to_string())?;
                manifest_note = format!("adopted remote (epoch {})", remote_m.snapshot_epoch);
                if remote_m.device(&me).map(|d| !d.active).unwrap_or(true) {
                    eprintln!("warning: this device is revoked in the new manifest");
                }
            }
            Ordering::Equal => {
                // Epochs bump on every owner-signed write, so equal epochs
                // with different bytes means two owner devices wrote
                // concurrently and ours lost the CAS race. The remote copy
                // is a real owner-signed manifest — adopt it; our unpushed
                // change must be redone.
                mpm_store::write_manifest(dir, &remote_bytes).map_err(|e| e.to_string())?;
                manifest_note = format!(
                    "adopted remote (epoch {}) — a local registry change lost a race; redo it",
                    remote_m.snapshot_epoch
                );
            }
            Ordering::Less => {
                if let Some(admin) = &cfg.admin {
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
                    manifest_note =
                        "local manifest ahead but no admin credential — pushed nothing".into();
                }
            }
        }
    }

    eprintln!("synced: pulled {pulled} op(s), pushed {pushed}, manifest {manifest_note}");
    Ok(())
}

/// Decode a page of pulled frames and check each against the manifest
/// registry BEFORE it lands in the local log: whole frames only (a
/// partial tail means corruption), strict seq continuity from
/// `first_seq`, and a valid device signature (verifiable without the
/// vault DEK — the sig covers seq·nonce·ct). Ops past `horizon` (a revoked
/// device's trust boundary) end the page early — validly signed but
/// untrusted, never appended. Returns `(frames, bytes)` verified.
fn verify_frames(
    buf: &[u8],
    device: &[u8; 16],
    first_seq: u64,
    device_vk: &[u8; 32],
    horizon: u64,
) -> Result<(usize, usize), String> {
    let (mut pos, mut n) = (0usize, 0usize);
    while pos < buf.len() {
        // the server caps pages at 256 — a larger page is off-contract
        if n >= 256 {
            return Err("pulled page exceeded the 256-frame cap".into());
        }
        let (op, end) = Op::decode(&buf[pos..]).map_err(|e| e.to_string())?;
        let want = first_seq + n as u64;
        if op.seq != want {
            return Err(format!(
                "pulled {} op seq {} — expected {want} (relay sent a gap/reorder)",
                mpm_store::hex(device),
                op.seq
            ));
        }
        if op.seq > horizon {
            break; // post-revocation ops: signed but untrusted — drop, don't fail
        }
        op.verify_sig(device_vk)
            .map_err(|_| format!("bad signature on pulled op seq {}", op.seq))?;
        pos += end;
        n += 1;
    }
    Ok((n, pos))
}

/// GET the relay's current manifest bytes — the CAS base every
/// owner-signed update must be built on.
fn fetch_remote_manifest(
    cfg: &SyncCfg,
    vault_id: &[u8; 16],
    token: &str,
) -> Result<Vec<u8>, String> {
    let r = http(
        "GET",
        &api(cfg, vault_id, "manifest"),
        Some(token),
        None,
        &[],
    )?;
    check(r.status, &r.body)?;
    unhex(&jstr(&json(&r.body)?, "manifest")?)
}

/// Serialize `sync` runs per vault: the daemon's background timer and a
/// manual `mypassman sync` must not interleave their pull/append loops.
/// Lives beside the .conf so it survives vault-dir moves/restores.
fn sync_lock(vault_id: &[u8; 16]) -> Result<std::fs::File, String> {
    use fs2::FileExt;
    let path = cfg_path(vault_id)?.with_extension("synclock");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    #[cfg(unix)]
    let f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(|e| e.to_string())?
    };
    #[cfg(not(unix))]
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| e.to_string())?;
    f.try_lock_exclusive()
        .map_err(|_| "another sync is already running for this vault".to_string())?;
    Ok(f)
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
    println!(
        "{:<34} {:<24} {:<14} CREATED",
        "DEVICE", "NAME", "VK-FINGERPRINT"
    );
    for p in &rows {
        println!(
            "{:<34} {:<24} {:<14} {}",
            jstr(p, "device")?,
            crate::disp(&jstr(p, "name")?),
            jstr(p, "vk")?
                .get(..16)
                .map(str::to_string)
                .unwrap_or_else(|| "?".into()),
            jnum(p, "created")?
        );
    }
    eprintln!("compare VK-FINGERPRINT with what the joining device printed before approving");
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
    if m.device(&dev_id).is_some() {
        return Err(format!(
            "device {} is already enrolled — refusing a duplicate registry entry",
            mpm_store::hex(&dev_id)
        ));
    }

    // Stale-base check BEFORE mutating: our modification must be built on
    // exactly what the relay holds, or the CAS below would silently
    // overwrite another owner's concurrent change.
    let local_bytes = std::fs::read(dir.join(mpm_store::MANIFEST)).map_err(|e| e.to_string())?;
    let remote_bytes = fetch_remote_manifest(&cfg, &m.vault_id, &admin)?;
    if remote_bytes != local_bytes {
        return Err("local manifest is out of date — run `mypassman sync` first".into());
    }

    // owner-signed manifest update — this IS the approval
    let mut vault = crate::unlock(dir, rec)?;
    vault.manifest.devices.push(mpm_core::DeviceEntry {
        id: dev_id,
        vk: dev_vk,
        name: dev_name.clone(),
        active: true,
        enrolled_at: mpm_core::vault::now_hlc(),
        revoked_seq: None,
        extra: Vec::new(),
    });
    // snapshot_epoch is the manifest revision — every owner-signed write
    // bumps it, so a replayed older manifest can never win a reconcile
    vault.manifest.snapshot_epoch += 1;
    let bytes = vault.manifest.to_file(&vault.bundle().owner_signing_key());
    mpm_store::write_manifest(dir, &bytes).map_err(|e| e.to_string())?;

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
        "approved '{}' ({}) — run `mypassman pair finish` on that device",
        crate::disp(&dev_name),
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
pub fn cmd_pair_join(
    dir: &Path,
    url: &str,
    invite: Option<&str>,
    name: &str,
) -> Result<(), String> {
    // argv → $MPM_INVITE → prompt: the code is a bearer credential until
    // finish burns it, so keep it out of shell history/`ps`
    let owned;
    let invite = match invite {
        Some(i) => i,
        None => {
            owned = std::env::var("MPM_INVITE")
                .inspect(|_| std::env::remove_var("MPM_INVITE"))
                .unwrap_or_else(|_| crate::read_line("invite (<vault_id>.<code>)"));
            owned.as_str()
        }
    };
    if dir.join(mpm_store::MANIFEST).exists() {
        return Err("vault already exists here — pair join is for a fresh directory".into());
    }
    check_url_scheme(url)?;
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

    // Prove the password BEFORE writing anything: unwrap a password slot
    // and anchor owner_vk to the bundle it yields. A wrong password or a
    // hostile manifest leaves the directory untouched. Cap the slots we
    // try — each attempt is an Argon2 run with server-chosen params.
    let pw = crate::read_password("master password: ");
    let mut ok = false;
    for slot in m
        .wrap_slots
        .iter()
        .filter(|s| s.slot_type == mpm_core::manifest::SLOT_PASSWORD)
        .take(8)
    {
        let Some((params, salt)) = &slot.kdf else {
            continue;
        };
        if params.check_bounds(crate::DEVICE_KDF_CAP_KIB).is_err() {
            continue;
        }
        if let Ok(kek) =
            mpm_crypto::kdf::derive_kek(pw.as_bytes(), salt, params).map_err(|e| e.to_string())
        {
            let kek = zeroize::Zeroizing::new(kek);
            if let Ok(bundle) = mpm_crypto::keys::KeyBundle::unwrap(
                &kek,
                &mpm_core::aad::wrap_slot(&vault_id, m.key_epoch, slot.slot_type),
                &slot.blob,
                m.key_epoch,
            ) {
                if bundle.owner_verifying_key() == m.owner_vk {
                    ok = true;
                    break;
                }
            }
        }
    }
    if !ok {
        return Err("master password didn't unwrap this vault".into());
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

    eprintln!(
        "requested as '{}' ({})",
        crate::disp(name),
        mpm_store::hex(&dev.id)
    );
    eprintln!(
        "my vk fingerprint: {}",
        &mpm_store::hex(&dev.verifying_key())[..16]
    );
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
    let me = mpm_store::load_device_key(&m.vault_id)
        .map_err(|e| e.to_string())?
        .id;

    let manifest_bytes = if let Some(invite) = cfg.invite.clone() {
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
        // Persist the minted tokens FIRST — the invite is already burned
        // server-side, so losing them here would leave no way to re-finish.
        save_cfg(&m.vault_id, &cfg)?;
        unhex(&jstr(&v, "manifest")?)?
    } else if cfg.read.is_some() && cfg.write.is_some() {
        // A previous finish died after minting tokens but before writing
        // the manifest — recover by adopting the relay's current copy.
        eprintln!("tokens already minted — recovering manifest from relay");
        let rtok = cfg.read.clone().unwrap();
        fetch_remote_manifest(&cfg, &m.vault_id, &rtok)?
    } else {
        return Err("no pending enrollment — already finished or never joined".into());
    };

    let rm = Manifest::from_file(&manifest_bytes).map_err(|e| e.to_string())?;
    if rm.vault_id != m.vault_id {
        return Err("server returned a manifest for a different vault".into());
    }
    // The server pinned owner_vk, but check anyway: a wrong-owner or
    // missing-device manifest would leave us holding useless tokens.
    if rm.owner_vk != m.owner_vk {
        return Err("server returned a manifest under a different owner key".into());
    }
    match rm.device(&me) {
        Some(d) if d.active => {}
        _ => {
            return Err(
                "approved manifest doesn't list this device as active — re-check on the owner side"
                    .into(),
            )
        }
    }
    mpm_store::write_manifest(dir, &manifest_bytes).map_err(|e| e.to_string())?;
    eprintln!("paired — pulling ops");
    cmd_sync(dir)?;
    eprintln!("enrollment complete");
    Ok(())
}

/// `mypassman pair revoke <device-prefix>` — the owner marks the device
/// inactive in the manifest (re-signed + pushed with CAS), then the server
/// burns its tokens. Revocation is forward-looking: the device keeps
/// whatever ciphertext it already pulled.
pub fn cmd_pair_revoke(dir: &Path, rec: bool, prefix: &str, keep_keys: bool) -> Result<(), String> {
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
        return Err(format!("'{}' is already revoked", crate::disp(&dev.name)));
    }
    let dev_hex = mpm_store::hex(&dev.id);
    let dev_name = dev.name.clone();

    // Stale-base check: the revoke must be built on the manifest the relay
    // actually holds, or the CAS below silently drops a concurrent change.
    let local_bytes = std::fs::read(dir.join(mpm_store::MANIFEST)).map_err(|e| e.to_string())?;
    let remote_bytes = fetch_remote_manifest(&cfg, &m.vault_id, &admin)?;
    if remote_bytes != local_bytes {
        return Err("local manifest is out of date — run `mypassman sync` first".into());
    }

    // Revocation horizon = the device's head on the relay: every op it
    // wrote while still trusted keeps merging on all replicas, so a lost
    // phone's history survives its own revocation. Ops beyond the horizon
    // (post-revocation writes) are rejected everywhere. Falls back to the
    // local log length if the relay has no head for the device.
    let horizon = {
        let r = http(
            "GET",
            &api(&cfg, &m.vault_id, "state"),
            Some(&admin),
            None,
            &[],
        )?;
        check(r.status, &r.body)?;
        json(&r.body)?
            .get("heads")
            .and_then(|h| h.as_array())
            .and_then(|hs| {
                hs.iter().find_map(|h| {
                    (h.get("device")?.as_str()? == dev_hex)
                        .then(|| h.get("head")?.as_u64())
                        .flatten()
                })
            })
            .or_else(|| {
                mpm_store::read_ops(dir, &dev.id)
                    .ok()
                    .and_then(|lr| lr.ops.last().map(|o| o.seq))
            })
            .unwrap_or(0)
    };

    // owner-signed manifest update — revoke IS a signature, not a flag
    let mut vault = crate::unlock(dir, rec)?;
    for d in &mut vault.manifest.devices {
        if mpm_store::hex(&d.id) == dev_hex {
            d.active = false;
            d.revoked_seq = Some(horizon);
        }
    }
    // Key rotation (default; --keep-keys skips): mint a new DEK epoch and
    // re-wrap every slot. The master password must change too — the revoked
    // device knew it and could otherwise just re-derive the same KEK and
    // unwrap the rotated bundle. Ops already written stay readable via DEK
    // history; anything sealed post-rotation is unreachable for the revoked
    // device even if it obtains the ciphertext.
    if !keep_keys {
        let epoch = vault.rotate_keys();
        eprintln!("rotating vault keys → key_epoch {epoch}");
        let vid = vault.manifest.vault_id;
        let mut pw_kek: Option<(mpm_crypto::kdf::KdfParams, [u8; 32], [u8; 32])> = None;
        let mut slots = Vec::with_capacity(vault.manifest.wrap_slots.len());
        for slot in &vault.manifest.wrap_slots {
            match slot.slot_type {
                mpm_core::manifest::SLOT_PASSWORD => {
                    if pw_kek.is_none() {
                        let p1 = crate::read_password("new master password: ");
                        let p2 = crate::read_password("confirm new password: ");
                        if *p1 != *p2 {
                            return Err("passwords don't match".into());
                        }
                        let mut salt = [0u8; 32];
                        crate::rand_core_fill(&mut salt);
                        let kek = mpm_crypto::kdf::derive_kek(
                            p1.as_bytes(),
                            &salt,
                            &slot.kdf.map(|(p, _)| p).unwrap_or_default(),
                        )
                        .map_err(|e| e.to_string())?;
                        pw_kek = Some((slot.kdf.map(|(p, _)| p).unwrap_or_default(), salt, kek));
                    }
                    let (params, salt, kek) = pw_kek.as_ref().unwrap();
                    let blob = vault
                        .bundle()
                        .wrap(
                            kek,
                            &mpm_core::aad::wrap_slot(
                                &vid,
                                epoch,
                                mpm_core::manifest::SLOT_PASSWORD,
                            ),
                        )
                        .map_err(|e| e.to_string())?;
                    slots.push(mpm_core::manifest::WrapSlot {
                        slot_type: mpm_core::manifest::SLOT_PASSWORD,
                        kdf: Some((*params, *salt)),
                        blob,
                        extra: Vec::new(),
                    });
                }
                mpm_core::manifest::SLOT_RECOVERY => {
                    // needs the physical kit — offer to retire it instead
                    let code = crate::read_password(
                        "recovery code to carry over (blank retires the kit): ",
                    );
                    if code.trim().is_empty() {
                        eprintln!(
                            "warning: recovery slot dropped — run `mypassman recovery` to mint a fresh kit"
                        );
                        continue;
                    }
                    let raw = mpm_core::recovery::parse_code(code.trim())
                        .map_err(|_| "malformed recovery code".to_string())?;
                    let mut salt = [0u8; 32];
                    crate::rand_core_fill(&mut salt);
                    let params = slot.kdf.map(|(p, _)| p).unwrap_or_default();
                    let kek = mpm_crypto::kdf::derive_kek(&raw, &salt, &params)
                        .map_err(|e| e.to_string())?;
                    let blob = vault
                        .bundle()
                        .wrap(
                            &kek,
                            &mpm_core::aad::wrap_slot(
                                &vid,
                                epoch,
                                mpm_core::manifest::SLOT_RECOVERY,
                            ),
                        )
                        .map_err(|e| e.to_string())?;
                    slots.push(mpm_core::manifest::WrapSlot {
                        slot_type: mpm_core::manifest::SLOT_RECOVERY,
                        kdf: Some((params, salt)),
                        blob,
                        extra: Vec::new(),
                    });
                }
                #[cfg(target_os = "macos")]
                mpm_core::manifest::SLOT_BIOMETRIC => {
                    // the keychain KEK lives on THIS machine — re-wrap if
                    // present, else the slot is useless post-rotation anyway
                    match crate::bio::load(&vid) {
                        Some(kek) => {
                            let blob = vault
                                .bundle()
                                .wrap(
                                    &kek,
                                    &mpm_core::aad::wrap_slot(
                                        &vid,
                                        epoch,
                                        mpm_core::manifest::SLOT_BIOMETRIC,
                                    ),
                                )
                                .map_err(|e| e.to_string())?;
                            slots.push(mpm_core::manifest::WrapSlot {
                                slot_type: mpm_core::manifest::SLOT_BIOMETRIC,
                                kdf: None,
                                blob,
                                extra: Vec::new(),
                            });
                        }
                        None => eprintln!(
                            "warning: no keychain key here — biometric slot dropped;                              re-run `mypassman bio on` on each device"
                        ),
                    }
                }
                _ => {
                    eprintln!(
                        "warning: unknown slot type {} dropped during rotation",
                        slot.slot_type
                    );
                }
            }
        }
        vault.manifest.wrap_slots = slots;
        eprintln!(
            "master password rotated — other devices must unlock with the new              password on next sync; their pre-rotation data stays intact"
        );
    }

    // bump the manifest revision — every owner-signed write does, so a
    // replayed pre-revoke manifest can never win a reconcile
    vault.manifest.snapshot_epoch += 1;
    let bytes = vault.manifest.to_file(&vault.bundle().owner_signing_key());
    mpm_store::write_manifest(dir, &bytes).map_err(|e| e.to_string())?;

    // CAS-push the manifest, then burn the device's tokens server-side
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
    eprintln!("revoked '{}' ({dev_hex})", crate::disp(&dev_name));
    eprintln!("note: it keeps whatever it already synced — rotate exposed secrets if needed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(seq: u64, ct_len: usize) -> Op {
        Op {
            seq,
            nonce: [0u8; 24],
            sig: [0u8; 64],
            ct: vec![0u8; ct_len],
        }
    }

    fn body_len(ops: &[&Op], (s, e): (usize, usize)) -> usize {
        ops[s..e]
            .iter()
            .map(|o| mpm_core::op::OP_HEADER_LEN + o.ct.len())
            .sum()
    }

    #[test]
    fn push_batches_respect_frame_cap() {
        // 300 small ops → two batches: 256 + 44
        let ops: Vec<Op> = (1..=300).map(|s| op(s, 32)).collect();
        let refs: Vec<&Op> = ops.iter().collect();
        let bounds = push_batch_bounds(&refs).unwrap();
        assert_eq!(bounds, vec![(0, 256), (256, 300)]);
        for b in &bounds {
            assert!(b.1 - b.0 <= PUSH_MAX_FRAMES);
            assert!(body_len(&refs, *b) <= PUSH_MAX_BYTES);
        }
    }

    #[test]
    fn push_batches_respect_byte_cap() {
        // ~256 KiB ciphertexts: the byte cap binds long before 256 frames
        let per = PUSH_MAX_BYTES / 4 - mpm_core::op::OP_HEADER_LEN;
        let ops: Vec<Op> = (1..=10).map(|s| op(s, per)).collect();
        let refs: Vec<&Op> = ops.iter().collect();
        let bounds = push_batch_bounds(&refs).unwrap();
        // each batch holds at most 4 such frames (5 would exceed 1 MiB)
        assert_eq!(bounds, vec![(0, 4), (4, 8), (8, 10)]);
        for b in &bounds {
            assert!(body_len(&refs, *b) <= PUSH_MAX_BYTES);
        }
    }

    #[test]
    fn push_batches_byte_cap_boundary() {
        // a frame that fits exactly ends the batch at exactly 1 MiB
        let big = PUSH_MAX_BYTES - mpm_core::op::OP_HEADER_LEN;
        let ops: Vec<Op> = vec![op(1, big), op(2, 0)];
        let refs: Vec<&Op> = ops.iter().collect();
        let bounds = push_batch_bounds(&refs).unwrap();
        assert_eq!(bounds, vec![(0, 1), (1, 2)]);
        assert_eq!(body_len(&refs, bounds[0]), PUSH_MAX_BYTES);
    }

    #[test]
    fn push_batches_reject_oversize_frame() {
        // one frame bigger than the body cap can never sync — loud error
        let ops: Vec<Op> = vec![op(1, 8), op(2, PUSH_MAX_BYTES), op(3, 8)];
        let refs: Vec<&Op> = ops.iter().collect();
        let err = push_batch_bounds(&refs).unwrap_err();
        assert!(err.contains("seq 2"), "{err}");
    }

    #[test]
    fn push_batches_empty() {
        assert!(push_batch_bounds(&[]).unwrap().is_empty());
    }
}
