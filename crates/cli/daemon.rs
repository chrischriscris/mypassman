//! Unlock daemon (DESIGN.md §M2): one Argon2 unlock, then commands served
//! over a private unix socket. Auto-lock = the process exits after an idle
//! TTL — Vault's KeyBundle is Zeroizing, so exit *is* the lock.
//!
//! Wire: `op u8 | len u32be | payload_tlv` → `status u8 | len | payload`.
//! Trust boundary: socket dir 0700 + socket 0600 + peer-uid check; a client
//! is the same user, so decrypted items may cross the wire — they never
//! touch argv/env/logs.
//!
//! Consistency: before serving each request the daemon re-reads its OWN op
//! log under the vault lock — a standalone CLI invocation appending while
//! the daemon sleeps must not fork the chain (same device, same seq space).
//! Foreign-device logs are replayed at startup only (real sync is M3).

#[cfg(unix)]
use crate::{find_one, save_checkpoint, unlock};
use mpm_core::item::ItemKind;
use mpm_core::tlv::{OrderGuard, Reader, Writer};
use mpm_core::Item;
#[cfg(unix)]
use mpm_core::Vault;
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::time::{Duration, Instant};

pub const OP_PING: u8 = 0;
pub const OP_LIST: u8 = 1;
pub const OP_ITEM: u8 = 2; // req T_NAME → resp T_ITEM (decrypted item tlv)
pub const OP_PUT: u8 = 3; // req {T_KIND,T_NAME,T_ITEM} → resp {T_RID,T_CREATED}
pub const OP_DEL: u8 = 4; // req T_NAME → empty
#[cfg(unix)]
pub const OP_LOCK: u8 = 5; // → daemon exits

const T_NAME: u8 = 0x01;
const T_KIND: u8 = 0x02;
const T_ITEM: u8 = 0x03;
const T_RECORD: u8 = 0x04;
const T_RID: u8 = 0x05;
const T_CREATED: u8 = 0x06;
const T_ERR: u8 = 0x07;

#[cfg(unix)]
const MAX_MSG: usize = 1 << 20; // 1 MiB — same-uid peer, but bound it anyway

// ── socket path ──────────────────────────────────────────────────────

#[cfg(unix)]
fn sock_dir() -> Result<PathBuf, String> {
    let base = dirs::data_local_dir().ok_or("no data dir")?;
    Ok(base.join("mypassman").join("sock"))
}

/// Socket for a vault: needs vault_id from the manifest (cheap read — the
/// id is inside the signed body but we only use it as a filename here).
#[cfg(unix)]
fn sock_path(dir: &Path) -> Option<PathBuf> {
    let m = mpm_store::load_manifest(dir).ok()?;
    Some(
        sock_dir()
            .ok()?
            .join(format!("{}.sock", mpm_store::hex(&m.vault_id))),
    )
}

// ── framing ──────────────────────────────────────────────────────────

#[cfg(unix)]
fn write_msg(
    s: &mut std::os::unix::net::UnixStream,
    tag: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let mut b = Vec::with_capacity(5 + payload.len());
    b.push(tag);
    b.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    b.extend_from_slice(payload);
    s.write_all(&b)
}

#[cfg(unix)]
fn read_msg(s: &mut std::os::unix::net::UnixStream) -> std::io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr)?;
    let len = u32::from_be_bytes(hdr) as usize;
    if len > MAX_MSG {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "oversize",
        ));
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

// ── peer auth ────────────────────────────────────────────────────────

/// Reject anyone who isn't us. macOS/BSD: getpeereid; Linux: SO_PEERCRED.
#[cfg(target_os = "macos")]
fn peer_is_us(s: &std::os::unix::net::UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    let (mut uid, mut gid) = (0u32, 0u32);
    unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) == 0 && uid == libc::geteuid() }
}

#[cfg(target_os = "linux")]
fn peer_is_us(s: &std::os::unix::net::UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    #[repr(C)]
    struct Ucred {
        pid: i32,
        uid: u32,
        gid: u32,
    }
    let mut c = Ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut l = std::mem::size_of::<Ucred>() as u32;
    unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut c as *mut _ as *mut libc::c_void,
            &mut l,
        ) == 0
            && c.uid == libc::geteuid()
    }
}

#[cfg(all(unix, not(target_os = "macos"), not(target_os = "linux")))]
fn peer_is_us(_s: &std::os::unix::net::UnixStream) -> bool {
    false // unknown unix: fail closed
}

// ── server ───────────────────────────────────────────────────────────

/// Entry point for `mpm daemon`. Holds the unlocked vault; exits on idle
/// TTL or OP_LOCK. Unix-only — other platforms fall back to per-command
/// unlocks (the client dispatch below just finds no socket).
#[cfg(unix)]
pub fn run(dir: &Path, rec: bool, idle_ttl: u64) -> Result<(), String> {
    use std::os::unix::net::UnixListener;

    let mut vault = unlock(dir, rec)?;
    let sdir = sock_dir()?;
    std::fs::create_dir_all(&sdir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sdir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
    }
    let path = sock_path(dir).ok_or("no manifest")?;
    if path.exists() {
        // stale socket from a dead daemon — bind over it
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    let listener =
        UnixListener::bind(&path).map_err(|e| format!("bind {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    eprintln!("daemon: vault unlocked, listening on {}", path.display());
    eprintln!("daemon: auto-locks after {idle_ttl}s idle — `mpm lock` to lock now");

    // ops already applied at startup — the refresh watermark
    let mut known = mpm_store::read_ops(dir, vault.device_id())
        .map(|l| l.ops.len())
        .unwrap_or(0);
    let mut last = Instant::now();
    let ttl = Duration::from_secs(idle_ttl);
    loop {
        match listener.accept() {
            Ok((mut s, _)) => {
                last = Instant::now();
                if !peer_is_us(&s) {
                    continue; // not our user — drop silently
                }
                s.set_nonblocking(false).ok();
                s.set_read_timeout(Some(Duration::from_secs(10))).ok();
                s.set_write_timeout(Some(Duration::from_secs(10))).ok();
                let mut op = [0u8; 1];
                if s.read_exact(&mut op).is_err() {
                    continue;
                }
                let payload = match read_msg(&mut s) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                if op[0] == OP_LOCK {
                    let _ = write_msg(&mut s, 0, b"");
                    break; // vault drops → keys zeroized → we exit
                }
                let (status, resp) = handle(op[0], &payload, &mut vault, dir, &mut known);
                let _ = write_msg(&mut s, status, &resp);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
        if last.elapsed() > ttl {
            eprintln!("daemon: idle ttl — locking");
            break;
        }
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Refresh in-memory state from our own op log if another process appended
/// while we slept. Fork/divergence → honest error (client falls back).
#[cfg(unix)]
fn refresh(vault: &mut Vault, dir: &Path, known: &mut usize) -> Result<(), String> {
    let _lock = mpm_store::lock_vault(dir).map_err(|e| e.to_string())?;
    let lr = mpm_store::read_ops(dir, vault.device_id()).map_err(|e| e.to_string())?;
    if lr.ops.len() < *known {
        return Err("op log shrank under the daemon — restart it".into());
    }
    for op in &lr.ops[*known..] {
        vault.apply_own_op(op).map_err(|e| e.to_string())?;
    }
    *known = lr.ops.len();
    Ok(())
}

#[cfg(unix)]
fn handle(
    op: u8,
    payload: &[u8],
    vault: &mut Vault,
    dir: &Path,
    known: &mut usize,
) -> (u8, Vec<u8>) {
    match serve(op, payload, vault, dir, known) {
        Ok(p) => (0, p),
        Err(e) => {
            let (status, msg) = if let Some(m) = e.strip_prefix("MISSING:") {
                (2u8, m.to_string())
            } else {
                (1u8, e)
            };
            let mut w = Writer::new();
            w.field(T_ERR, msg.as_bytes());
            (status, w.finish())
        }
    }
}

#[cfg(unix)]
fn serve(
    op: u8,
    payload: &[u8],
    vault: &mut Vault,
    dir: &Path,
    known: &mut usize,
) -> Result<Vec<u8>, String> {
    if op == OP_PING {
        return Ok(Vec::new());
    }

    // catch up with any out-of-band appends before answering
    refresh(vault, dir, known).map_err(|e| format!("refresh: {e}"))?;

    match op {
        OP_LIST => {
            let mut w = Writer::new();
            let mut rows: Vec<_> = vault.records().collect();
            rows.sort_by(|a, b| a.name.cmp(&b.name));
            for r in rows {
                let mut inner = Writer::new();
                inner.field(T_KIND, &[r.kind.map(|k| k as u8).unwrap_or(0)]);
                inner.field(T_NAME, r.name.as_bytes());
                inner.field(T_RID, &r.record_id);
                w.field(T_RECORD, &inner.finish());
            }
            Ok(w.finish())
        }
        OP_ITEM => {
            let name = tlv_str(payload, T_NAME)?;
            match find_one(vault, &name) {
                Ok(rid) => {
                    let item = vault.item(&rid).map_err(|e| e.to_string())?;
                    let kind = vault
                        .records()
                        .find(|r| r.record_id == rid)
                        .and_then(|r| r.kind);
                    let mut w = Writer::new();
                    if let Some(k) = kind {
                        w.field(T_KIND, &[k as u8]);
                    }
                    if let Some(r) = vault.records().find(|r| r.record_id == rid) {
                        w.field(T_NAME, r.name.as_bytes());
                    }
                    w.field(T_ITEM, &item.encode());
                    Ok(w.finish())
                }
                Err(e) => Err(format!("MISSING:{e}")),
            }
        }
        OP_PUT => {
            let mut r = Reader::new(payload);
            let (mut kind, mut name, mut tlv) = (None, None, None);
            let mut ord = OrderGuard::default();
            while let Some((t, v)) = r.next_field().map_err(|e| e.to_string())? {
                ord.check(t, &[]).map_err(|e| e.to_string())?;
                match t {
                    T_KIND => kind = Some(v[0]),
                    T_NAME => name = Some(String::from_utf8_lossy(v).into_owned()),
                    T_ITEM => tlv = Some(v.to_vec()),
                    _ => {}
                }
            }
            let (kind, name, tlv) = (kind, name, tlv);
            let (Some(kv), Some(name), Some(tlv)) = (kind, name, tlv) else {
                return Err("PUT: missing fields".into());
            };
            let kind = ItemKind::from_u8(kv).map_err(|e| e.to_string())?;
            let item = Item::decode(&tlv).map_err(|e| e.to_string())?;
            // exact-name semantics: same kind → update in place; other kind
            // → refuse (prevents silent name collision)
            let existing = vault
                .records()
                .find(|r| r.name == name)
                .map(|r| (r.record_id, r.kind));
            let (op, created, rid) = match existing {
                Some((rid, Some(k))) if k == kind => (
                    vault
                        .make_update(&rid, kind, item)
                        .map_err(|e| e.to_string())?,
                    false,
                    rid,
                ),
                Some((_, Some(k))) => {
                    return Err(format!("'{name}' exists as {} — rm it first", k.name()))
                }
                Some((_, None)) => return Err(format!("'{name}' exists with unknown kind")),
                None => {
                    let (op, rid) = vault.make_upsert(kind, item).map_err(|e| e.to_string())?;
                    (op, true, rid)
                }
            };
            mpm_store::append_op(dir, vault.device_id(), &op).map_err(|e| e.to_string())?;
            vault.commit(&op).map_err(|e| e.to_string())?;
            *known += 1;
            save_checkpoint(vault)?;
            let mut w = Writer::new();
            w.field(T_RID, &rid);
            w.field(T_CREATED, &[created as u8]);
            Ok(w.finish())
        }
        OP_DEL => {
            let name = tlv_str(payload, T_NAME)?;
            let rid = find_one(vault, &name).map_err(|e| format!("MISSING:{e}"))?;
            let op = vault.make_tombstone(&rid).map_err(|e| e.to_string())?;
            mpm_store::append_op(dir, vault.device_id(), &op).map_err(|e| e.to_string())?;
            vault.commit(&op).map_err(|e| e.to_string())?;
            *known += 1;
            save_checkpoint(vault)?;
            Ok(Vec::new())
        }
        _ => Err(format!("unknown op {op}")),
    }
}

fn tlv_str(payload: &[u8], tag: u8) -> Result<String, String> {
    let mut r = Reader::new(payload);
    while let Some((t, v)) = r.next_field().map_err(|e| e.to_string())? {
        if t == tag {
            return Ok(String::from_utf8_lossy(v).into_owned());
        }
    }
    Err("missing field".into())
}

// ── client ───────────────────────────────────────────────────────────

fn daemon_enabled() -> bool {
    std::env::var_os("MPM_NO_DAEMON").is_none()
}

/// One round-trip. `Ok(None)` = no live daemon → caller uses the
/// standalone path. `Err` = daemon answered with an error (don't fall
/// back — the daemon's view is authoritative when it's alive).
#[cfg(unix)]
fn call(dir: &Path, op: u8, payload: &[u8]) -> Result<Option<(u8, Vec<u8>)>, String> {
    use std::os::unix::net::UnixStream;
    if !daemon_enabled() {
        return Ok(None);
    }
    let Some(path) = sock_path(dir) else {
        return Ok(None);
    };
    let mut s = match UnixStream::connect(&path) {
        Ok(s) => s,
        Err(_) => return Ok(None), // absent/stale socket → standalone path
    };
    s.set_read_timeout(Some(Duration::from_secs(30))).ok();
    s.set_write_timeout(Some(Duration::from_secs(30))).ok();
    write_msg(&mut s, op, payload).map_err(|e| e.to_string())?;
    let mut status = [0u8; 1];
    s.read_exact(&mut status).map_err(|e| e.to_string())?;
    let resp = read_msg(&mut s).map_err(|e| e.to_string())?;
    if status[0] == 1 {
        return Err(tlv_str(&resp, T_ERR).unwrap_or_else(|_| "daemon error".into()));
    }
    Ok(Some((status[0], resp)))
}

#[cfg(not(unix))]
fn call(_dir: &Path, _op: u8, _payload: &[u8]) -> Result<Option<(u8, Vec<u8>)>, String> {
    Ok(None)
}

fn name_payload(name: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.field(T_NAME, name.as_bytes());
    w.finish()
}

pub enum DaemonItem {
    /// (item, kind, record-name) — name lives in the op's outer layer, so
    /// the daemon returns it separately; clients must re-set NAME on PUT.
    Found(Item, Option<ItemKind>, String),
    Missing, // daemon is alive and says no such record (or ambiguous)
    Offline, // no daemon → caller uses the standalone path
}

/// Fetch a decrypted item via the daemon.
pub fn item(dir: &Path, name: &str) -> Result<DaemonItem, String> {
    match call(dir, OP_ITEM, &name_payload(name))? {
        Some((0, p)) => {
            let (mut kind, mut item, mut name) = (None, None, String::new());
            let mut r = Reader::new(&p);
            while let Some((t, v)) = r.next_field().map_err(|e| e.to_string())? {
                match t {
                    T_KIND => kind = ItemKind::from_u8(v[0]).ok(),
                    T_NAME => name = String::from_utf8_lossy(v).into_owned(),
                    T_ITEM => item = Some(Item::decode(v).map_err(|e| e.to_string())?),
                    _ => {}
                }
            }
            Ok(DaemonItem::Found(
                item.ok_or("daemon: no item")?,
                kind,
                name,
            ))
        }
        Some((2, _)) => Ok(DaemonItem::Missing),
        Some((s, _)) => Err(format!("daemon: unexpected status {s}")),
        None => Ok(DaemonItem::Offline),
    }
}

pub type ListRow = (Option<ItemKind>, String, String);

/// List rows via the daemon: (kind, name, record_id hex).
pub fn try_list(dir: &Path) -> Result<Option<Vec<ListRow>>, String> {
    match call(dir, OP_LIST, &[])? {
        Some((0, p)) => {
            let mut out = Vec::new();
            let mut r = Reader::new(&p);
            let mut ord = OrderGuard::default();
            while let Some((t, v)) = r.next_field().map_err(|e| e.to_string())? {
                ord.check(t, &[T_RECORD]).map_err(|e| e.to_string())?;
                if t != T_RECORD {
                    continue;
                }
                let (mut kind, mut name, mut rid) = (None, String::new(), String::new());
                let mut ir = Reader::new(v);
                while let Some((it, iv)) = ir.next_field().map_err(|e| e.to_string())? {
                    match it {
                        T_KIND => kind = ItemKind::from_u8(iv[0]).ok(),
                        T_NAME => name = String::from_utf8_lossy(iv).into_owned(),
                        T_RID => {
                            let id: &[u8; 16] = iv.try_into().unwrap_or(&[0u8; 16]);
                            rid = mpm_store::hex(id);
                        }
                        _ => {}
                    }
                }
                out.push((kind, name, rid));
            }
            Ok(Some(out))
        }
        Some((s, _)) => Err(format!("daemon: unexpected status {s}")),
        None => Ok(None),
    }
}

/// Create-or-update via the daemon. Returns (record_id, created).
pub fn try_put(
    dir: &Path,
    kind: ItemKind,
    name: &str,
    item: &Item,
) -> Result<Option<([u8; 16], bool)>, String> {
    let mut w = Writer::new();
    w.field(T_NAME, name.as_bytes()); // canonical order: NAME(1) < KIND(2) < ITEM(3)
    w.field(T_KIND, &[kind as u8]);
    w.field(T_ITEM, &item.encode());
    match call(dir, OP_PUT, &w.finish())? {
        Some((0, p)) => {
            let (mut rid, mut created) = (None, false);
            let mut r = Reader::new(&p);
            while let Some((t, v)) = r.next_field().map_err(|e| e.to_string())? {
                match t {
                    T_RID => rid = v.try_into().ok(),
                    T_CREATED => created = v.first().copied() == Some(1),
                    _ => {}
                }
            }
            Ok(Some((rid.ok_or("daemon: no rid")?, created)))
        }
        Some((s, _)) => Err(format!("daemon: unexpected status {s}")),
        None => Ok(None),
    }
}

/// Tombstone via the daemon.
pub fn try_del(dir: &Path, name: &str) -> Result<Option<()>, String> {
    match call(dir, OP_DEL, &name_payload(name))? {
        Some((0, _)) => Ok(Some(())),
        Some((2, p)) => Err(tlv_str(&p, T_ERR).unwrap_or_else(|_| "not found".into())),
        Some((s, _)) => Err(format!("daemon: unexpected status {s}")),
        None => Ok(None),
    }
}

/// `mpm lock`: tell a live daemon to exit. Ok(false) = nothing running.
pub fn lock(dir: &Path) -> Result<bool, String> {
    let _ = dir;
    if !daemon_enabled() {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        if sock_path(dir).is_none() {
            return Ok(false);
        }
    }
    #[cfg(not(unix))]
    {
        return Ok(false);
    }
    #[cfg(unix)]
    match call(dir, OP_LOCK, &[]) {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Is a daemon answering PING for this vault?
pub fn alive(dir: &Path) -> bool {
    matches!(call(dir, OP_PING, &[]), Ok(Some(_)))
}
