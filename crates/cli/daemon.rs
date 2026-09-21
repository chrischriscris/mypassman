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
//! Foreign-device logs are also refreshed per request: a `sync` pull appends
//! them on disk and the daemon merges the verified suffix without a
//! re-unlock.

#[cfg(unix)]
use crate::{find_one, save_checkpoint, unlock};
use mpm_core::item::ItemKind;
use mpm_core::tlv::{OrderGuard, Reader, Writer};
use mpm_core::Item;
#[cfg(unix)]
use mpm_core::Vault;
#[cfg(unix)]
use std::collections::HashMap;
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
const T_META: u8 = 0x08; // LIST row: inner TLV {field_tag → value} non-secret only
const T_FIELDS: u8 = 0x09; // LIST row: raw u8 tag list — every field incl. secrets

#[cfg(unix)]
const MAX_MSG: usize = 1 << 20; // 1 MiB — same-uid peer, but bound it anyway

// ── socket path ──────────────────────────────────────────────────────

#[cfg(unix)]
fn sock_dir() -> Result<PathBuf, String> {
    let base = dirs::data_local_dir().ok_or("no data dir")?;
    Ok(base.join("mypassman").join("sock"))
}

/// Socket for a vault dir: keyed by the canonical path, not vault_id —
/// two dirs can hold the same vault (two devices on one machine) and must
/// NOT share a daemon: each dir signs ops as its own device, so routing
/// dir B to dir A's daemon would silently attribute B's writes to A.
#[cfg(unix)]
fn sock_path(dir: &Path) -> Option<PathBuf> {
    let canon = std::fs::canonicalize(dir).ok()?;
    let key = blake3::hash(canon.to_string_lossy().as_bytes()).to_hex();
    // sun_path is ~104 bytes on unix — keep the name short like the old
    // vault_id-based one (128-bit tag is plenty to avoid collisions).
    Some(sock_dir().ok()?.join(format!("{}.sock", &key[..32])))
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
    use fs2::FileExt;
    use std::os::unix::net::UnixListener;

    // Singleton BEFORE the password prompt: a second daemon must never
    // unlink a live one's socket (the orphan stays unlocked but
    // unreachable — `mpm lock` couldn't find it). The flock outlives us
    // only while we hold it.
    let sdir = sock_dir()?;
    std::fs::create_dir_all(&sdir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sdir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
    }
    let path = sock_path(dir).ok_or("no manifest")?;
    let lck = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path.with_extension("daemon.lock"))
        .map_err(|e| e.to_string())?;
    lck.try_lock_exclusive()
        .map_err(|_| "daemon already running for this vault".to_string())?;
    if path.exists() {
        // flock says no live daemon — but if a peer answers anyway (lock
        // file deleted under a running daemon), refuse rather than orphan it
        if std::os::unix::net::UnixStream::connect(&path).is_ok() {
            return Err("live daemon socket present — refusing to replace it".into());
        }
        std::fs::remove_file(&path).map_err(|e| e.to_string())?; // stale
    }
    // foreign log tips recorded BEFORE unlock: ops appended between this
    // read and unlock's replay get re-verified as a harmless idempotent
    // suffix — recording tips after unlock would instead mark frames seen
    // that were never applied
    let mut foreign: HashMap<[u8; 16], (u64, [u8; 32])> = HashMap::new();
    let mut quarantined: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
    for dev in mpm_store::list_device_logs(dir).map_err(|e| e.to_string())? {
        let lr = mpm_store::read_ops(dir, &dev).map_err(|e| e.to_string())?;
        if let Some(tip) = lr.ops.last() {
            foreign.insert(dev, (tip.seq, tip.hash()));
        }
    }
    let mut vault = unlock(dir, rec)?;
    foreign.remove(vault.device_id()); // own log is tracked by `known`, not `foreign`
                                       // a log fully covered by the adopted snapshot has no on-disk tip —
                                       // its verified position is the anchor, else the daemon would re-verify
                                       // the dropped prefix on every refresh
    for (dev, tip) in foreign.iter_mut() {
        if tip.0 == 0 {
            if let Some(a) = vault.anchor(dev) {
                *tip = a;
            }
        }
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

    // ops applied at startup — derive from the vault's own replay head,
    // not a fresh read (an op appended between unlock and a re-read would
    // be counted-but-never-applied → our next append forks the chain)
    let mut known = vault.head().0;
    // background sync: opportunistic ciphertext exchange — never needs the
    // unlocked vault (sync transports ciphertext only), so it runs while we
    // serve. Pulled foreign ops land on disk and merge into the index on
    // the next request via refresh_foreign. MPM_SYNC_EVERY=0 disables.
    if sync_interval() > 0 {
        let dir = dir.to_path_buf();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(sync_interval()));
            if let Err(e) = crate::sync::cmd_sync(&dir) {
                // expected misses: unconfigured vault, or a manual sync
                // already holding the sync lock — neither is a failure
                if !e.contains("no sync config") && !e.contains("another sync") {
                    eprintln!("daemon: background sync: {e}");
                }
            }
        });
    }
    let mut last = Instant::now();
    let ttl = Duration::from_secs(idle_ttl);
    loop {
        match listener.accept() {
            Ok((mut s, _)) => {
                // a conn accepted after the deadline is NOT served — the
                // vault is already supposed to be locked
                if last.elapsed() > ttl {
                    eprintln!("daemon: idle ttl — locking");
                    break;
                }
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
                // OP_PUT payloads carry item plaintext — wipe on drop
                let payload = match read_msg(&mut s) {
                    Ok(p) => zeroize::Zeroizing::new(p),
                    Err(_) => continue,
                };
                if op[0] == OP_LOCK {
                    let _ = write_msg(&mut s, 0, b"");
                    break; // vault drops → keys zeroized → we exit
                }
                if op[0] == OP_PING {
                    // aliveness probe — no vault lock, no state, and it
                    // does NOT count as activity toward the idle TTL
                    let _ = write_msg(&mut s, 0, b"");
                    continue;
                }
                // vault lock held across refresh→append→commit: an
                // out-of-band writer between refresh and append would
                // fork our own log otherwise
                let _lock = match mpm_store::lock_vault(dir) {
                    Ok(l) => l,
                    Err(e) => {
                        let mut w = Writer::new();
                        w.field(T_ERR, e.to_string().as_bytes());
                        let _ = write_msg(&mut s, 1, &w.finish());
                        continue;
                    }
                };
                let (status, resp) = handle(
                    op[0],
                    payload.as_slice(),
                    &mut vault,
                    dir,
                    &mut known,
                    &mut foreign,
                    &mut quarantined,
                );
                let _ = write_msg(&mut s, status, &resp);
                if op[0] != OP_PING {
                    last = Instant::now(); // only real ops reset idle
                }
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

/// Sentinel: on-disk state changed shape under the daemon (compaction,
/// restore, log rewrite) — rebuild the index from scratch rather than
/// erroring the request.
#[cfg(unix)]
const REBUILD: &str = "rebuild";

/// Refresh in-memory state from our own op log if another process appended
/// while we slept. CALLER HOLDS THE VAULT LOCK. `known` is the last applied
/// SEQ (not a count — compaction drops prefixes). Shrink/divergence/gaps
/// that only a snapshot anchor can bridge → REBUILD.
#[cfg(unix)]
fn refresh(vault: &mut Vault, dir: &Path, known: &mut u64) -> Result<bool, String> {
    let lr = mpm_store::read_ops(dir, vault.device_id()).map_err(|e| e.to_string())?;
    let torn = lr.torn_tail;
    let own = *vault.device_id();
    let disk_tip = lr
        .ops
        .last()
        .map(|o| o.seq)
        .or_else(|| vault.anchor(&own).map(|a| a.0))
        .unwrap_or(0);
    if disk_tip < *known {
        return Err(REBUILD.into()); // shrank — compaction or worse
    }
    // same length ≠ same log: an op at our tip seq must hash to our head
    match lr.ops.iter().find(|o| o.seq == *known) {
        Some(o) if o.hash() != vault.head().1 => return Err(REBUILD.into()),
        None if *known > 0 => {
            // tip op itself was covered+dropped — anchor must match
            match vault.anchor(&own) {
                Some((s, h)) if s == *known && h == vault.head().1 => {}
                _ => return Err(REBUILD.into()),
            }
        }
        _ => {}
    }
    let Some(i) = lr.ops.iter().position(|o| o.seq > *known) else {
        return Ok(torn); // nothing new
    };
    let first_new = lr.ops[i].seq;
    if first_new > *known + 1 {
        // covered gap — only the adopted anchor can bridge it
        match vault.anchor(&own) {
            Some((s, _)) if s + 1 == first_new && s >= *known => vault.apply_own_anchor(),
            _ => return Err(REBUILD.into()),
        }
    }
    for op in &lr.ops[i..] {
        vault.apply_own_op(op).map_err(|_| REBUILD.to_string())?;
        *known = op.seq;
    }
    Ok(torn)
}

/// Merge sync-pulled foreign ops: `sync` appends raw frames to
/// ops/<device>.log while the daemon sleeps. Each request verifies and
/// applies just the suffix past the last tip we saw — shrinkage or a
/// diverged tip is honest failure, same posture as the own-log check.
#[cfg(unix)]
fn refresh_foreign(
    vault: &mut Vault,
    dir: &Path,
    foreign: &mut HashMap<[u8; 16], (u64, [u8; 32])>,
    quarantined: &mut std::collections::HashSet<[u8; 16]>,
) -> Result<(), String> {
    let devs = mpm_store::list_device_logs(dir).map_err(|e| e.to_string())?;
    if devs.iter().all(|d| d == vault.device_id()) {
        return Ok(());
    }
    // foreign logs exist → the on-disk manifest may have moved (device
    // add/revoke via pair syncs as a manifest push). Reload it: ops from a
    // device our in-memory copy doesn't know — or still trusts after a
    // revocation — must verify against the CURRENT registry.
    reload_manifest(vault, dir)?;
    for dev in devs {
        if &dev == vault.device_id() || quarantined.contains(&dev) {
            continue;
        }
        let (cnt, head) = foreign.get(&dev).copied().unwrap_or((0, [0u8; 32]));
        let lr = mpm_store::read_ops(dir, &dev).map_err(|e| e.to_string())?;
        // disk tip by SEQ — post-compaction logs start mid-chain
        let disk_tip = lr
            .ops
            .last()
            .map(|o| o.seq)
            .or_else(|| vault.anchor(&dev).map(|a| a.0))
            .unwrap_or(0);
        if disk_tip < cnt {
            return Err(REBUILD.into()); // shrank — compaction or tamper
        }
        if disk_tip == cnt {
            continue;
        }
        let Some(i) = lr.ops.iter().position(|o| o.seq > cnt) else {
            continue;
        };
        let first_new = lr.ops[i].seq;
        // continuity: contiguous → chain from our stored tip; a covered
        // gap → the adopted snapshot anchor bridges it
        let (start, prev) = if first_new == cnt + 1 {
            (cnt + 1, head)
        } else {
            match vault.anchor(&dev) {
                Some((s, h)) if s + 1 == first_new && s >= cnt => (first_new, h),
                _ => return Err(REBUILD.into()),
            }
        };
        // prefix verify: a revoked device still contributes ops up to its
        // revocation horizon; a failure quarantines the log (warn once)
        // rather than erroring every request until restart
        let r = vault.verify_foreign_prefix(&dev, &lr.ops[i..], start, prev);
        vault.apply_foreign(&r.pts);
        foreign.insert(dev, r.tip);
        if let Some((seq, e)) = r.failed_at {
            // warn once — a quarantined log keeps tripping the same frame
            if quarantined.insert(dev) {
                eprintln!(
                    "daemon: quarantined log of device {} at seq {} ({e})",
                    mpm_store::hex(&dev),
                    seq
                );
            }
        }
    }
    Ok(())
}

/// Rebuild the daemon's whole view: reload the manifest (still
/// epoch-pinned), reset the vault, replay from snapshot base + log
/// suffixes. Handles compaction, restores, and log rewrites uniformly.
#[cfg(unix)]
fn rebuild(
    vault: &mut Vault,
    dir: &Path,
    known: &mut u64,
    foreign: &mut HashMap<[u8; 16], (u64, [u8; 32])>,
    quarantined: &mut std::collections::HashSet<[u8; 16]>,
) -> Result<(), String> {
    reload_manifest(vault, dir)?;
    vault.reset();
    let rep = crate::replay_state(vault, dir)?;
    *known = vault.head().0;
    foreign.clear();
    quarantined.clear();
    for (dev, tip) in rep.tips {
        if dev != *vault.device_id() {
            foreign.insert(dev, tip);
        }
    }
    eprintln!("daemon: rebuilt vault state after on-disk change");
    Ok(())
}

/// Pick up a manifest written while the daemon slept (device add/revoke).
/// Refuses anything beyond a registry/snapshot-epoch change — a key_epoch
/// move re-encrypts op AAD and this process's DEK replay is stale.
#[cfg(unix)]
fn reload_manifest(vault: &mut Vault, dir: &Path) -> Result<(), String> {
    let m = mpm_store::load_manifest(dir).map_err(|e| e.to_string())?;
    if m.vault_id != vault.manifest.vault_id
        || m.owner_vk != vault.manifest.owner_vk
        || m.key_epoch != vault.manifest.key_epoch
        || m.snapshot_epoch < vault.manifest.snapshot_epoch
    {
        return Err("manifest changed incompatibly — restart the daemon".into());
    }
    vault.manifest = m;
    Ok(())
}

#[cfg(unix)]
fn handle(
    op: u8,
    payload: &[u8],
    vault: &mut Vault,
    dir: &Path,
    known: &mut u64,
    foreign: &mut HashMap<[u8; 16], (u64, [u8; 32])>,
    quarantined: &mut std::collections::HashSet<[u8; 16]>,
) -> (u8, Vec<u8>) {
    let r = serve(op, payload, vault, dir, known, foreign, quarantined);
    let r = match r {
        Err(e) if e == REBUILD => {
            if let Err(re) = rebuild(vault, dir, known, foreign, quarantined) {
                Err(format!("rebuild: {re}"))
            } else {
                serve(op, payload, vault, dir, known, foreign, quarantined)
            }
        }
        r => r,
    };
    match r {
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
    known: &mut u64,
    foreign: &mut HashMap<[u8; 16], (u64, [u8; 32])>,
    quarantined: &mut std::collections::HashSet<[u8; 16]>,
) -> Result<Vec<u8>, String> {
    // catch up with any out-of-band appends before answering (the caller
    // holds the vault lock across the whole request)
    let torn = refresh(vault, dir, known).map_err(|e| {
        if e == REBUILD {
            e
        } else {
            format!("refresh: {e}")
        }
    })?;
    refresh_foreign(vault, dir, foreign, quarantined).map_err(|e| {
        if e == REBUILD {
            e
        } else {
            format!("refresh: {e}")
        }
    })?;
    if torn && matches!(op, OP_PUT | OP_DEL) {
        // appending past the tear would orphan the new op at next unlock
        return Err(
            "op log has a torn tail — refusing to write (backup+restore rebuilds clean)".into(),
        );
    }

    match op {
        OP_LIST => {
            let mut w = Writer::new();
            let mut rows: Vec<_> = vault.records().collect();
            rows.sort_by(|a, b| a.name.cmp(&b.name));
            // the client reads at most MAX_MSG (1 MiB) — meta values are
            // already capped per-field, but 500 fat rows would still
            // overflow the aggregate. Budget meta bytes; rows past the
            // budget get an empty map (fields/kind still arrive).
            let mut meta_budget: usize = 768 * 1024;
            for r in rows {
                let mut inner = Writer::new();
                inner.field(T_NAME, r.name.as_bytes()); // canonical: 1 < 2 < 5 < 8 < 9
                inner.field(T_KIND, &[r.kind.map(|k| k as u8).unwrap_or(0)]);
                inner.field(T_RID, &r.record_id);
                let (tags, ns) = crate::row_meta_tags(vault, &r.record_id);
                let mut meta = Writer::new();
                for (t, v) in &ns {
                    let cost = v.len() + 4; // tag+len encoding overhead
                    if cost > meta_budget {
                        break;
                    }
                    meta_budget -= cost;
                    meta.field(*t, v);
                }
                inner.field(T_META, &meta.finish());
                inner.field(T_FIELDS, &tags);
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
                    let enc = zeroize::Zeroizing::new(item.encode());
                    let mut w = Writer::new();
                    if let Some(r) = vault.records().find(|r| r.record_id == rid) {
                        w.field(T_NAME, r.name.as_bytes()); // canonical: 1<2<3<5
                    }
                    if let Some(k) = kind {
                        w.field(T_KIND, &[k as u8]);
                    }
                    w.field(T_ITEM, &enc);
                    w.field(T_RID, &rid);
                    Ok(w.finish())
                }
                Err(e) => Err(format!("MISSING:{e}")),
            }
        }
        OP_PUT => {
            let mut r = Reader::new(payload);
            let (mut kind, mut name, mut tlv, mut want_rid) = (None, None, None, None);
            let mut ord = OrderGuard::default();
            while let Some((t, v)) = r.next_field().map_err(|e| e.to_string())? {
                ord.check(t, &[]).map_err(|e| e.to_string())?;
                match t {
                    T_KIND => {
                        if v.len() != 1 {
                            return Err("PUT: bad kind".into());
                        }
                        kind = Some(v[0]);
                    }
                    T_NAME => {
                        let n = String::from_utf8(v.to_vec())
                            .map_err(|_| "PUT: name not utf-8".to_string())?;
                        if n.is_empty() || n.chars().any(|c| c.is_control()) {
                            return Err("PUT: bad name".into());
                        }
                        name = Some(n);
                    }
                    T_ITEM => tlv = Some(zeroize::Zeroizing::new(v.to_vec())),
                    T_RID => want_rid = Some(<[u8; 16]>::try_from(v).map_err(|_| "PUT: bad rid")?),
                    _ => {}
                }
            }
            let (kind, name, tlv) = (kind, name, tlv);
            let (Some(kv), Some(name), Some(tlv)) = (kind, name, tlv) else {
                return Err("PUT: missing fields".into());
            };
            let kind = ItemKind::from_u8(kv).map_err(|e| e.to_string())?;
            let item = Item::decode(&tlv).map_err(|e| e.to_string())?;
            // T_RID → update-only, addressed by id (edit semantics): a
            // fetch→delete→put sequence must NOT silently create
            let (op, created, rid) = if let Some(rid) = want_rid {
                let rec = vault
                    .records()
                    .find(|r| r.record_id == rid)
                    .map(|r| (r.tombstoned, r.kind));
                match rec {
                    Some((false, Some(k))) => (
                        vault
                            .make_update(&rid, k, item)
                            .map_err(|e| e.to_string())?,
                        false,
                        rid,
                    ),
                    Some((false, None)) => return Err("record kind unknown".into()),
                    _ => return Err("MISSING:record gone — nothing updated".into()),
                }
            } else {
                // exact-name semantics: same kind → update in place; other kind
                // → refuse (prevents silent name collision)
                let existing = vault
                    .records()
                    .find(|r| r.name == name)
                    .map(|r| (r.record_id, r.kind));
                match existing {
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
    /// (item, kind, record-name, record-id) — name/id live in the op's
    /// outer layer, so the daemon returns them separately; clients must
    /// re-set NAME on PUT and pass rid for update-only edits.
    Found(Item, Option<ItemKind>, String, [u8; 16]),
    Missing, // daemon is alive and says no such record (or ambiguous)
    Offline, // no daemon → caller uses the standalone path
}

/// Fetch a decrypted item via the daemon.
pub fn item(dir: &Path, name: &str) -> Result<DaemonItem, String> {
    match call(dir, OP_ITEM, &name_payload(name))? {
        Some((0, p)) => {
            let (mut kind, mut item, mut name, mut rid) = (None, None, String::new(), None);
            let mut r = Reader::new(&p);
            while let Some((t, v)) = r.next_field().map_err(|e| e.to_string())? {
                match t {
                    T_KIND if v.len() == 1 => kind = ItemKind::from_u8(v[0]).ok(),
                    T_NAME => name = String::from_utf8_lossy(v).into_owned(),
                    T_ITEM => item = Some(Item::decode(v).map_err(|e| e.to_string())?),
                    T_RID => rid = <[u8; 16]>::try_from(v).ok(),
                    _ => {}
                }
            }
            Ok(DaemonItem::Found(
                item.ok_or("daemon: no item")?,
                kind,
                name,
                rid.ok_or("daemon: no rid")?,
            ))
        }
        Some((2, _)) => Ok(DaemonItem::Missing),
        Some((s, _)) => Err(format!("daemon: unexpected status {s}")),
        None => Ok(DaemonItem::Offline),
    }
}

pub struct ListRow {
    pub kind: Option<ItemKind>,
    pub name: String,
    pub rid: String,
    /// every field name present (secret presence is metadata, not a secret)
    pub fields: Vec<String>,
    /// non-secret (name, value) pairs only — secret values never cross
    pub meta: Vec<(String, String)>,
}

/// List rows via the daemon: kind/name/rid + field names + non-secret meta.
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
                let mut row = ListRow {
                    kind: None,
                    name: String::new(),
                    rid: String::new(),
                    fields: Vec::new(),
                    meta: Vec::new(),
                };
                let mut ir = Reader::new(v);
                while let Some((it, iv)) = ir.next_field().map_err(|e| e.to_string())? {
                    match it {
                        T_KIND if iv.len() == 1 => row.kind = ItemKind::from_u8(iv[0]).ok(),
                        T_NAME => row.name = String::from_utf8_lossy(iv).into_owned(),
                        T_RID => {
                            let id: &[u8; 16] = iv.try_into().unwrap_or(&[0u8; 16]);
                            row.rid = mpm_store::hex(id);
                        }
                        T_FIELDS => {
                            // ≤256 tag bytes exist; more is wire garbage —
                            // don't let it amplify into heap strings
                            if iv.len() <= 256 {
                                row.fields = iv.iter().map(|t| crate::tag_name(*t)).collect();
                            }
                        }
                        T_META => {
                            let mut mr = Reader::new(iv);
                            while let Some((mt, mv)) = mr.next_field().map_err(|e| e.to_string())? {
                                // re-classify client-side: a hostile or
                                // buggy producer can't smuggle secret-tag
                                // values into the metadata channel
                                if crate::tag_secret(mt) {
                                    continue;
                                }
                                row.meta.push((
                                    crate::tag_name(mt),
                                    String::from_utf8_lossy(mv).into_owned(),
                                ));
                            }
                        }
                        _ => {}
                    }
                }
                out.push(row);
            }
            Ok(Some(out))
        }
        Some((s, _)) => Err(format!("daemon: unexpected status {s}")),
        None => Ok(None),
    }
}

/// Create-or-update via the daemon. `rid: Some` → update-only addressed
/// by record id (edit); `None` → upsert by name (add).
pub fn try_put(
    dir: &Path,
    kind: ItemKind,
    name: &str,
    rid: Option<&[u8; 16]>,
    item: &Item,
) -> Result<Option<([u8; 16], bool)>, String> {
    let enc = zeroize::Zeroizing::new(item.encode());
    let mut w = Writer::new();
    w.field(T_NAME, name.as_bytes()); // canonical order: 1 < 2 < 3 < 5
    w.field(T_KIND, &[kind as u8]);
    w.field(T_ITEM, &enc);
    if let Some(r) = rid {
        w.field(T_RID, r);
    }
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

/// Background sync period (seconds). `MPM_SYNC_EVERY` overrides; 0 disables.
#[cfg(unix)]
fn sync_interval() -> u64 {
    std::env::var("MPM_SYNC_EVERY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300)
}
