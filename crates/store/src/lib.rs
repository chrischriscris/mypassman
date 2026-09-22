//! Vault storage: `vault/` directory layout (DESIGN.md §5/§7).
//!
//!   <vault>/MANIFEST        owner_sig || manifest_tlv
//!   <vault>/ops/<device>.log  append-only op stream
//!   <vault>/snapshots/       compacted state (post-M3)
//!
//! Device private keys live OUTSIDE the synced vault dir under the OS
//! data dir — a device key must never be replicated by file sync.

use fs2::FileExt;
use mpm_core::op::Op;
use mpm_core::Manifest;
use mpm_crypto::DeviceKey;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("core: {0}")]
    Core(#[from] mpm_core::CoreError),
    #[error("vault already exists at {0}")]
    Exists(PathBuf),
    #[error("no vault at {0}")]
    NoVault(PathBuf),
    #[error("no device key for this vault on this machine")]
    NoDeviceKey,
    #[error("vault is busy (another mypassman process holds the write lock)")]
    Busy,
    #[error("op log rolled back or diverged from last verified checkpoint")]
    RolledBack,
}

pub type Result<T> = std::result::Result<T, StoreError>;

pub const MANIFEST: &str = "MANIFEST";
pub const OPS_DIR: &str = "ops";
pub const SNAPS_DIR: &str = "snapshots";

/// Initialize a fresh vault directory (fails if it already contains one).
pub fn init_dir(dir: &Path) -> Result<()> {
    if dir.join(MANIFEST).exists() {
        return Err(StoreError::Exists(dir.to_path_buf()));
    }
    // mode set at creation — no 0755→0700 chmod window
    private_dirs().create(dir.join(OPS_DIR))?;
    private_dirs().create(dir.join(SNAPS_DIR))?;
    set_private_dir(dir)?; // belt+braces: an existing parent may pre-date us
    Ok(())
}

pub fn load_manifest(dir: &Path) -> Result<Manifest> {
    let path = dir.join(MANIFEST);
    if !path.exists() {
        return Err(StoreError::NoVault(dir.to_path_buf()));
    }
    let buf = fs::read(path)?;
    Ok(Manifest::from_file(&buf)?)
}

/// Exclusive write lock for the vault (flock). Hold across
/// read-modify-write sequences or two processes can append the same seq.
/// Lock file is never truncated, so a pre-planted symlink is harmless.
pub fn lock_vault(dir: &Path) -> Result<File> {
    // .append would be wrong here (the lock file must not grow), and we
    // never write through this handle at all — flock is the whole point
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(".lock"))?;
    f.try_lock_exclusive().map_err(|_| StoreError::Busy)?;
    Ok(f)
}

/// Durable manifest write: unique tmp (O_EXCL — never follows a planted
/// symlink) → fsync → rename → fsync dir.
pub fn write_manifest(dir: &Path, bytes: &[u8]) -> Result<()> {
    // unique per call within the process too — concurrent same-dir writes
    // must not share a tmp path (one's error-cleanup would delete the
    // other's file under rename)
    static TMPN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp = dir.join(format!(
        ".MANIFEST.{}.{}.tmp",
        std::process::id(),
        TMPN.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let dst = dir.join(MANIFEST);
    let res = (|| -> Result<()> {
        {
            let mut f = private_files().create_new(true).open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &dst)?;
        fsync_dir(dir)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    set_private_file(&dst)?;
    res
}

pub fn log_path(dir: &Path, device_id: &[u8; 16]) -> PathBuf {
    dir.join(OPS_DIR).join(format!("{}.log", hex(device_id)))
}

/// Append a canonical op and fsync — the file AND the ops dir (a new
/// log's directory entry is not durable without the second fsync).
pub fn append_op(dir: &Path, device_id: &[u8; 16], op: &Op) -> Result<()> {
    let path = log_path(dir, device_id);
    let mut f = private_files().create(true).append(true).open(&path)?;
    // fd-level check: refuse to append into a non-regular file (planted
    // symlink/hardlink). The opened fd pins the object — no TOCTOU here.
    if !f.metadata()?.is_file() {
        return Err(StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "op log is not a regular file",
        )));
    }
    set_private_file(&path)?;
    f.write_all(&op.encode())?;
    f.sync_all()?;
    fsync_dir(&dir.join(OPS_DIR))?;
    Ok(())
}

/// Append already-encoded frames to a log — the sync path's variant of
/// `append_op` (pulled frames arrive pre-encoded and are stored verbatim).
/// Same rules: 0600, regular-file check on the open fd, fsync file + dir.
pub fn append_frames(dir: &Path, device_id: &[u8; 16], frames: &[u8]) -> Result<()> {
    let path = log_path(dir, device_id);
    let mut f = private_files().create(true).append(true).open(&path)?;
    if !f.metadata()?.is_file() {
        return Err(StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "op log is not a regular file",
        )));
    }
    set_private_file(&path)?;
    f.write_all(frames)?;
    f.sync_all()?;
    fsync_dir(&dir.join(OPS_DIR))?;
    Ok(())
}

/// Truncate a log to `len` bytes — used to drop a torn tail before
/// re-pulling. Only ever called under the sync lock, and only ever
/// shrinks (the dropped bytes are by definition unverified).
pub fn truncate_log(dir: &Path, device_id: &[u8; 16], len: u64) -> Result<()> {
    let path = log_path(dir, device_id);
    let f = private_files().write(true).open(&path)?;
    if !f.metadata()?.is_file() {
        return Err(StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "op log is not a regular file",
        )));
    }
    if f.metadata()?.len() < len {
        return Err(StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "truncate_log only shrinks",
        )));
    }
    f.set_len(len)?;
    f.sync_all()?;
    Ok(())
}

/// Result of reading a device log: verified-prefix ops plus a flag for a
/// torn tail (crash mid-append leaves a truncated final record — that is
/// expected damage, distinct from mid-log corruption which stays fatal).
pub struct LogRead {
    pub ops: Vec<Op>,
    pub torn_tail: bool,
}

/// Read all ops from a device log, in order. A truncated final record is
/// reported as `torn_tail` rather than failing the whole log.
pub fn read_ops(dir: &Path, device_id: &[u8; 16]) -> Result<LogRead> {
    let path = log_path(dir, device_id);
    let mut buf = Vec::new();
    match File::open(&path) {
        Ok(mut f) => {
            f.read_to_end(&mut buf)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LogRead {
                ops: Vec::new(),
                torn_tail: false,
            })
        }
        Err(e) => return Err(e.into()),
    }
    let mut ops = Vec::new();
    let mut pos = 0usize;
    let mut torn_tail = false;
    while pos < buf.len() {
        match Op::decode(&buf[pos..]) {
            Ok((op, end)) => {
                ops.push(op);
                pos += end;
            }
            // a torn write can only ever be the last record
            Err(_) if pos > 0 => {
                torn_tail = true;
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(LogRead { ops, torn_tail })
}

/// Rewrite a device log keeping only ops with `seq > covered_seq` — the
/// physical half of checkpoint adoption. Atomic (tmp + rename + fsync);
/// frames are copied verbatim so signatures and hashes are untouched.
/// Only ever called under the vault write lock.
pub fn drop_covered_prefix(dir: &Path, device_id: &[u8; 16], covered_seq: u64) -> Result<usize> {
    let path = log_path(dir, device_id);
    let lr = read_ops(dir, device_id)?;
    let keep: Vec<u8> = lr
        .ops
        .iter()
        .filter(|o| o.seq > covered_seq)
        .flat_map(|o| o.encode())
        .collect();
    let old_len = path.metadata().map(|m| m.len()).unwrap_or(0);
    if keep.len() as u64 == old_len {
        return Ok(0); // nothing covered on disk
    }
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    {
        let mut f = private_files().create_new(true).open(&tmp)?;
        f.write_all(&keep)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    fsync_dir(&dir.join(OPS_DIR))?;
    Ok((old_len - keep.len() as u64) as usize)
}

// ── snapshots (adopted checkpoint ops, inside the synced vault dir) ──
//
// A snapshot file is just the raw checkpoint op frame — self-authenticating
// (device signature + DEK-sealed body). But signature alone is NOT enough
// to adopt it: the winner-set claim must have been verified against a
// replay of the covered ops. That check is only possible while the covered
// ops still exist, so a replica that ran it leaves a durable proof behind:
// `<author>.ok`, an owner-key signature over the frame hash. A vault-dir
// writer cannot forge the attestation (the owner key lives only inside
// sealed bundles), and it survives backup/restore under a fresh device key.

fn snap_path(dir: &Path, author: &[u8; 16]) -> PathBuf {
    dir.join(SNAPS_DIR).join(format!("{}.snap", hex(author)))
}

fn att_path(dir: &Path, author: &[u8; 16]) -> PathBuf {
    dir.join(SNAPS_DIR).join(format!("{}.ok", hex(author)))
}

/// Persist an adopted checkpoint frame + its claim attestation (one per
/// author — a newer checkpoint from the same author supersedes).
pub fn save_snapshot(dir: &Path, author: &[u8; 16], frame: &[u8], att: &[u8; 64]) -> Result<()> {
    let path = snap_path(dir, author);
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    {
        let mut f = private_files().create_new(true).open(&tmp)?;
        f.write_all(frame)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    let apath = att_path(dir, author);
    let atmp = apath.with_extension(format!("{}.tmp", std::process::id()));
    {
        let mut f = private_files().create_new(true).open(&atmp)?;
        f.write_all(att)?;
        f.sync_all()?;
    }
    fs::rename(&atmp, &apath)?;
    fsync_dir(&dir.join(SNAPS_DIR))?;
    set_private_file(&path)?;
    set_private_file(&apath)?;
    Ok(())
}

/// A stored snapshot frame: (author_device_id, op, attestation).
pub type SnapshotEntry = ([u8; 16], Op, Option<[u8; 64]>);

/// All stored snapshot frames. A present-but-malformed `.ok` is treated
/// as missing — the caller then refuses blind adoption exactly as if it
/// were absent.
pub fn load_snapshots(dir: &Path) -> Result<Vec<SnapshotEntry>> {
    let mut out = Vec::new();
    let snaps = dir.join(SNAPS_DIR);
    if !snaps.exists() {
        return Ok(out);
    }
    for e in fs::read_dir(snaps)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(id) = name.strip_suffix(".snap").and_then(unhex16) else {
            continue;
        };
        let buf = fs::read(e.path())?;
        let att = match fs::read(att_path(dir, &id)) {
            Ok(b) => <[u8; 64]>::try_from(b.as_slice()).ok(),
            Err(_) => None,
        };
        match Op::decode(&buf) {
            Ok((op, end)) if end == buf.len() => out.push((id, op, att)),
            _ => continue, // torn/corrupt snapshot — ignorable, it's a cache
        }
    }
    Ok(out)
}

/// Drop a snapshot file that failed verification or was superseded by a
/// deeper checkpoint — never fatal to unlock. The attestation goes with
/// it: an orphaned `.ok` must never vouch for a different file.
pub fn remove_snapshot(dir: &Path, author: &[u8; 16]) -> Result<()> {
    for p in [snap_path(dir, author), att_path(dir, author)] {
        match fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// The adopted covered vector, stored UNENCRYPTED (device ids, seqs, and
/// op hashes — none secret; the relay already sees them) so the sync path
/// can compute pull cursors without unlocking the vault.
pub fn save_base_vector(dir: &Path, covered: &[mpm_core::op::Gossip]) -> Result<()> {
    let mut buf = Vec::with_capacity(covered.len() * mpm_core::op::Gossip::LEN);
    for g in covered {
        buf.extend_from_slice(&g.encode_pub());
    }
    let path = dir.join(SNAPS_DIR).join("base.vec");
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    {
        let mut f = private_files().create_new(true).open(&tmp)?;
        f.write_all(&buf)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    set_private_file(&path)?;
    Ok(())
}

/// Read the adopted covered vector — (device → covered seq). Advisory
/// only: a wrong value can waste a re-pull but cannot forge ops (frames
/// are signature-verified regardless).
pub fn load_base_vector(dir: &Path) -> Result<Vec<([u8; 16], u64)>> {
    let buf = match fs::read(dir.join(SNAPS_DIR).join("base.vec")) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    if buf.len() % mpm_core::op::Gossip::LEN != 0 {
        return Ok(Vec::new()); // torn — advisory data, just ignore it
    }
    let mut out = Vec::with_capacity(buf.len() / mpm_core::op::Gossip::LEN);
    for chunk in buf.chunks(mpm_core::op::Gossip::LEN) {
        let mut dev = [0u8; 16];
        dev.copy_from_slice(&chunk[..16]);
        let seq = u64::from_le_bytes(chunk[16..24].try_into().unwrap());
        out.push((dev, seq));
    }
    Ok(out)
}

/// List device log files present in the vault (hex device ids).
pub fn list_device_logs(dir: &Path) -> Result<Vec<[u8; 16]>> {
    let mut out = Vec::new();
    let ops_dir = dir.join(OPS_DIR);
    if !ops_dir.exists() {
        return Ok(out);
    }
    for e in fs::read_dir(ops_dir)? {
        let name = e?.file_name().to_string_lossy().into_owned();
        if let Some(hexpart) = name.strip_suffix(".log") {
            if let Some(id) = unhex16(hexpart) {
                out.push(id);
            }
        }
    }
    // readdir order is filesystem-dependent — sort so every caller sees a
    // stable scan (merge itself is order-independent, but logs and audit
    // output shouldn't be)
    out.sort_unstable();
    Ok(out)
}

// ── device keys (OUTSIDE the vault dir) ─────────────────────────────

fn device_dir() -> Result<PathBuf> {
    // MPM_DATA relocates the whole per-user store (device keys, sync
    // creds) — needed to host two devices of one vault on one machine
    // (tests, restore drills); each keeps its own key file.
    if let Some(d) = std::env::var_os("MPM_DATA") {
        return Ok(PathBuf::from(d).join("devices"));
    }
    let base = dirs::data_local_dir().ok_or_else(|| {
        StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no data dir",
        ))
    })?;
    Ok(base.join("mypassman").join("devices"))
}

fn device_key_path(vault_id: &[u8; 16]) -> Result<PathBuf> {
    Ok(device_dir()?.join(format!("{}.dev", hex(vault_id))))
}

/// File layout: device_id(16) || seed(32). Mode 0600.
pub fn save_device_key(vault_id: &[u8; 16], key: &DeviceKey) -> Result<()> {
    let dir = device_dir()?;
    private_dirs().create(&dir)?;
    set_private_dir(&dir)?;
    let path = device_key_path(vault_id)?;
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(48));
    buf.extend_from_slice(&key.id);
    buf.extend_from_slice(key.seed_bytes());
    // mode at creation: the seed must never exist at 0644, even briefly
    let mut f = private_files().create(true).truncate(true).open(&path)?;
    f.write_all(&buf)?;
    f.sync_all()?;
    set_private_file(&path)?;
    Ok(())
}

pub fn load_device_key(vault_id: &[u8; 16]) -> Result<DeviceKey> {
    let path = device_key_path(vault_id)?;
    let buf = zeroize::Zeroizing::new(fs::read(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => StoreError::NoDeviceKey,
        _ => StoreError::Io(e),
    })?);
    if buf.len() != 48 {
        return Err(StoreError::NoDeviceKey);
    }
    let mut id = [0u8; 16];
    let mut seed = [0u8; 32];
    id.copy_from_slice(&buf[..16]);
    seed.copy_from_slice(&buf[16..48]);
    Ok(DeviceKey::from_bytes(&seed, id))
}

// ── head checkpoints (outside the synced vault dir) ─────────────────
//
// The op log's tail is self-authenticating, but a *prefix rollback*
// (truncating the log, deleting it) verifies cleanly against genesis.
// The checkpoint persists the last head WE verified, signed by this
// device, so a shortened/diverged log is caught at unlock.
//
// File: sig(64) || device_id(16) || seq(8) || head(32); the signature
// covers "mypassman/v1/ckpt" | vault_id | device_id | seq | head.

const CKPT_DOMAIN: &[u8] = b"mypassman/v1/ckpt";

fn ckpt_path(vault_id: &[u8; 16]) -> Result<PathBuf> {
    Ok(device_dir()?.join(format!("{}.head", hex(vault_id))))
}

fn ckpt_preimage(vault_id: &[u8; 16], device_id: &[u8; 16], seq: u64, head: &[u8; 32]) -> Vec<u8> {
    let mut p = Vec::with_capacity(CKPT_DOMAIN.len() + 16 + 16 + 8 + 32);
    p.extend_from_slice(CKPT_DOMAIN);
    p.extend_from_slice(vault_id);
    p.extend_from_slice(device_id);
    p.extend_from_slice(&seq.to_le_bytes());
    p.extend_from_slice(head);
    p
}

/// Persist the verified log tip. `seq` is the op's seq (0 for empty log).
pub fn save_checkpoint(
    vault_id: &[u8; 16],
    device: &DeviceKey,
    seq: u64,
    head: &[u8; 32],
) -> Result<()> {
    let dir = device_dir()?;
    private_dirs().create(&dir)?;
    let sig = device.sign(&ckpt_preimage(vault_id, &device.id, seq, head));
    let mut buf = Vec::with_capacity(64 + 16 + 8 + 32);
    buf.extend_from_slice(&sig.to_bytes());
    buf.extend_from_slice(&device.id);
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(head);
    let path = ckpt_path(vault_id)?;
    // unique tmp + rename: never partial, never follows a planted symlink
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    {
        let mut f = private_files().create_new(true).open(&tmp)?;
        f.write_all(&buf)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    set_private_file(&path)?;
    Ok(())
}

/// Raw checkpoint bytes — used by `restore` to put the OLD checkpoint
/// back if the restored vault fails verification (a failed restore must
/// not erase the rollback protection of the vault it replaces).
pub fn read_checkpoint_raw(vault_id: &[u8; 16]) -> Result<Option<Vec<u8>>> {
    match fs::read(ckpt_path(vault_id)?) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Write raw checkpoint bytes back (restore-failure path only — normal
/// writes go through the device-signed `save_checkpoint`).
pub fn write_checkpoint_raw(vault_id: &[u8; 16], buf: &[u8]) -> Result<()> {
    let dir = device_dir()?;
    private_dirs().create(&dir)?;
    let path = ckpt_path(vault_id)?;
    let tmp = path.with_extension(format!("{}.r.tmp", std::process::id()));
    {
        let mut f = private_files().create_new(true).open(&tmp)?;
        f.write_all(buf)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    set_private_file(&path)?;
    Ok(())
}

/// Remove the stored checkpoint for a vault — used ONLY by `restore`,
/// which is a deliberate, user-invoked rollback. After the restored vault
/// verifies, the next unlock re-baselines the checkpoint to its head.
pub fn clear_checkpoint(vault_id: &[u8; 16]) -> Result<()> {
    match fs::remove_file(ckpt_path(vault_id)?) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// A verified checkpoint for this device: (seq, head).
pub fn load_checkpoint(vault_id: &[u8; 16], device: &DeviceKey) -> Result<Option<(u64, [u8; 32])>> {
    let buf = match fs::read(ckpt_path(vault_id)?) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if buf.len() != 120 {
        return Err(StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "checkpoint corrupt",
        )));
    }
    let sig = ed25519_dalek::Signature::from_bytes(&buf[..64].try_into().unwrap());
    let device_id: [u8; 16] = buf[64..80].try_into().unwrap();
    let seq = u64::from_le_bytes(buf[80..88].try_into().unwrap());
    let head: [u8; 32] = buf[88..120].try_into().unwrap();
    if device_id != device.id {
        return Ok(None); // belongs to a different device incarnation
    }
    let ok = mpm_crypto::keys::verify(
        &device.verifying_key(),
        &ckpt_preimage(vault_id, &device_id, seq, &head),
        &sig,
    )
    .is_ok();
    if !ok {
        return Err(StoreError::RolledBack);
    }
    Ok(Some((seq, head)))
}

// ── durability / permissions ────────────────────────────────────────

/// OpenOptions with 0600 baked into creation (unix) — secrets are born
/// private instead of being chmod'd after the fact. On other platforms the
/// ACL model differs; this is a no-op there.
fn private_files() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o
}

fn private_dirs() -> fs::DirBuilder {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b
}

fn fsync_dir(dir: &Path) -> Result<()> {
    File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn set_private_file(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(unix)]
fn set_private_dir(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file(_p: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir(_p: &Path) -> Result<()> {
    Ok(())
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex16(s: &str) -> Option<[u8; 16]> {
    // ascii-only: slicing a str at arbitrary byte offsets panics on
    // multibyte chars — a crafted 32-byte filename could crash unlock.
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
