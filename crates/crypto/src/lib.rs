//! mypassman crypto primitives.
//!
//! Key hierarchy (see DESIGN.md §5):
//!   password ─Argon2id→ KEK ─wraps→ KeyBundle { DEK, owner_sign_seed }
//!   DEK ─blake3 derive_key→ k_ops / k_rec / k_meta
//!   owner_sign / device_sign (Ed25519) authenticate manifest, registry, ops.

pub mod aead;
pub mod kdf;
pub mod keys;
pub mod subkey;

pub use aead::{open, seal, NONCE_LEN};
pub use ed25519_dalek::Signature;
pub use kdf::{derive_kek, KdfParams};
pub use keys::{DeviceKey, KeyBundle, SigningKeyBytes, VerifyingKeyBytes, KEY_LEN};
pub use subkey::{derive_record_key, derive_subkey, CTX_META, CTX_OPS, CTX_RECORD};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("argon2: {0}")]
    Argon2(String),
    #[error("kdf parameters out of bounds")]
    KdfBounds,
    #[error("aead open failed")]
    Aead,
    #[error("bad key/signature bytes")]
    BadKey,
    #[error("signature verify failed")]
    BadSignature,
    #[error("short input")]
    ShortInput,
}

pub type Result<T> = std::result::Result<T, CryptoError>;
