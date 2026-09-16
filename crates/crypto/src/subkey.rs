//! BLAKE3 derive_key with fixed context strings — domain separation by
//! construction. Never reuse a context across purposes.

/// Ops' outer AEAD layer — hides the record graph from the server; a
/// DEK-holder sees record metadata but not field secrets.
pub const CTX_OPS: &str = "mypassman/v1/ops";
/// Per-record field layer — decrypt-on-demand stays real.
pub const CTX_RECORD: &str = "mypassman/v1/record";
/// Non-authoritative metadata MAC.
pub const CTX_META: &str = "mypassman/v1/meta";

pub fn derive_subkey(dek: &[u8; 32], ctx: &str) -> [u8; 32] {
    blake3::derive_key(ctx, dek)
}

pub fn derive_record_key(dek: &[u8; 32], record_id: &[u8; 16]) -> zeroize::Zeroizing<[u8; 32]> {
    let mut material = zeroize::Zeroizing::new([0u8; 48]);
    material[..32].copy_from_slice(dek);
    material[32..].copy_from_slice(record_id);
    zeroize::Zeroizing::new(blake3::derive_key(CTX_RECORD, &material[..]))
}
