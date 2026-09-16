use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("crypto: {0}")]
    Crypto(#[from] mpm_crypto::CryptoError),
    #[error("malformed TLV: {0}")]
    Tlv(&'static str),
    #[error("duplicate TLV tag {0:#x}")]
    DupTag(u8),
    #[error("bad field length for tag {0:#x}")]
    BadLen(u8),
    #[error("unknown item kind {0}")]
    BadKind(u8),
    #[error("unknown op type {0}")]
    BadOpType(u8),
    #[error("unknown wrap slot type {0}")]
    BadSlot(u8),
    #[error("manifest signature invalid")]
    BadManifestSig,
    #[error("op signature invalid at seq {0}")]
    BadOpSig(u64),
    #[error("hash chain break at seq {0}")]
    ChainBreak(u64),
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u16),
    #[error("no wrap slot could be opened (bad password?)")]
    UnlockFailed,
    #[error("record not found")]
    NotFound,
    #[error("device not enrolled")]
    NotEnrolled,
}

pub type Result<T> = std::result::Result<T, CoreError>;
