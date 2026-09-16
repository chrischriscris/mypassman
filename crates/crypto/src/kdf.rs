use crate::{CryptoError, Result};
use argon2::{Algorithm, Argon2, Params, Version};

/// Argon2id parameters stored in the manifest. `m_kib` is memory in KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    /// Desktop default: 64 MiB, 3 iterations, 1 lane.
    fn default() -> Self {
        Self { m_kib: 65_536, t: 3, p: 1 }
    }
}

/// Hard cap on hostile manifest values — validated BEFORE allocation.
/// 1 GiB memory / 16 passes / 8 lanes is the absolute ceiling.
pub const KDF_MAX_M_KIB: u32 = 1_048_576;
pub const KDF_MAX_T: u32 = 16;
pub const KDF_MAX_P: u32 = 8;

impl KdfParams {
    pub fn check_bounds(&self, device_cap_kib: u32) -> Result<()> {
        if self.m_kib == 0
            || self.m_kib > KDF_MAX_M_KIB
            || self.m_kib > device_cap_kib
            || self.t == 0
            || self.t > KDF_MAX_T
            || self.p == 0
            || self.p > KDF_MAX_P
        {
            return Err(CryptoError::KdfBounds);
        }
        Ok(())
    }
}

/// Derive a 32-byte KEK from a password. `params` must already be
/// bounds-checked (hostile input can otherwise request absurd memory).
pub fn derive_kek(password: &[u8], salt: &[u8; 32], params: &KdfParams) -> Result<[u8; 32]> {
    let p = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;
    Ok(out)
}
