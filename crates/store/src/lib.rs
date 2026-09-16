//! Vault storage: `vault/` directory layout (DESIGN.md §5/§7).
//!
//!   <vault>/MANIFEST        owner_sig || manifest_tlv
//!   <vault>/ops/<device>.log  append-only op stream
//!   <vault>/snapshots/       compacted state (post-M3)
//!
//! Device private keys live OUTSIDE the synced vault dir under the OS
//! data dir — a device key must never be replicated by file sync.

use mpm_core::op::{Op, OP_HEADER_LEN};
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
    fs::create_dir_all(dir.join(OPS_DIR))?;
    fs::create_dir_all(dir.join(SNAPS_DIR))?;
    set_private_dir(dir)?;
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

/// Durable manifest write: tmp → fsync → rename → fsync dir.
pub fn write_manifest(dir: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = dir.join(".MANIFEST.tmp");
    let dst = dir.join(MANIFEST);
    {
        let mut f = File::create(&tmp)?;
        set_private_file(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &dst)?;
    fsync_dir(dir)
}

pub fn log_path(dir: &Path, device_id: &[u8; 16]) -> PathBuf {
    dir.join(OPS_DIR).join(format!("{}.log", hex(device_id)))
}

/// Append a canonical op and fsync. Ops are self-delimiting.
pub fn append_op(dir: &Path, device_id: &[u8; 16], op: &Op) -> Result<()> {
    let path = log_path(dir, device_id);
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    set_private_file(&path)?;
    f.write_all(&op.encode())?;
    f.sync_all()?;
    Ok(())
}

/// Read all ops from a device log, in order.
pub fn read_ops(dir: &Path, device_id: &[u8; 16]) -> Result<Vec<Op>> {
    let path = log_path(dir, device_id);
    let mut buf = Vec::new();
    match File::open(&path) {
        Ok(mut f) => {
            f.read_to_end(&mut buf)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    }
    let mut ops = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        if buf.len() - pos < OP_HEADER_LEN {
            return Err(mpm_core::CoreError::Tlv("trailing partial op").into());
        }
        let (op, end) = Op::decode(&buf[pos..])?;
        ops.push(op);
        pos += end;
    }
    Ok(ops)
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
    Ok(out)
}

// ── device keys (OUTSIDE the vault dir) ─────────────────────────────

fn device_dir() -> Result<PathBuf> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| StoreError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "no data dir")))?;
    Ok(base.join("mypassman").join("devices"))
}

fn device_key_path(vault_id: &[u8; 16]) -> Result<PathBuf> {
    Ok(device_dir()?.join(format!("{}.dev", hex(vault_id))))
}

/// File layout: device_id(16) || seed(32). Mode 0600.
pub fn save_device_key(vault_id: &[u8; 16], key: &DeviceKey) -> Result<()> {
    let dir = device_dir()?;
    fs::create_dir_all(&dir)?;
    set_private_dir(&dir)?;
    let path = device_key_path(vault_id)?;
    let mut buf = Vec::with_capacity(48);
    buf.extend_from_slice(&key.id);
    buf.extend_from_slice(key.seed_bytes());
    fs::write(&path, &buf)?;
    set_private_file(&path)?;
    Ok(())
}

pub fn load_device_key(vault_id: &[u8; 16]) -> Result<DeviceKey> {
    let path = device_key_path(vault_id)?;
    let buf = fs::read(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => StoreError::NoDeviceKey,
        _ => StoreError::Io(e),
    })?;
    if buf.len() != 48 {
        return Err(StoreError::NoDeviceKey);
    }
    let mut id = [0u8; 16];
    let mut seed = [0u8; 32];
    id.copy_from_slice(&buf[..16]);
    seed.copy_from_slice(&buf[16..48]);
    Ok(DeviceKey::from_bytes(&seed, id))
}

// ── durability / permissions ────────────────────────────────────────

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
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
