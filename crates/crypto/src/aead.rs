use crate::{CryptoError, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

/// Seal `msg` under XChaCha20-Poly1305 with an explicit random nonce.
/// `aad` is the caller-supplied canonical binding (see core::aad).
pub fn seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg, aad })
        .map_err(|_| CryptoError::Aead)
}

/// Open `ct` (includes the 16-byte tag). Fails closed on any tamper.
pub fn open(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| CryptoError::Aead)
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut n);
    n
}
