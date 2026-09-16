//! Canonical AAD construction — fixed-length fields, fixed order, no
//! ambiguity (DESIGN.md §5).

use crate::{DEVICE_ID_LEN, VAULT_ID_LEN};

/// Outer op-layer AAD: vault_id|format_v|key_epoch|device_id|seq — 46 bytes.
/// `format_v` comes from the MANIFEST (the version the op was written
/// under), never a compile-time constant — else bumping FORMAT_VERSION
/// would make every existing op undecryptable.
pub fn op(
    vault_id: &[u8; VAULT_ID_LEN],
    format_v: u16,
    key_epoch: u32,
    device_id: &[u8; DEVICE_ID_LEN],
    seq: u64,
) -> [u8; 46] {
    let mut a = [0u8; 46];
    a[0..16].copy_from_slice(vault_id);
    a[16..18].copy_from_slice(&format_v.to_le_bytes());
    a[18..22].copy_from_slice(&key_epoch.to_le_bytes());
    a[22..38].copy_from_slice(device_id);
    a[38..46].copy_from_slice(&seq.to_le_bytes());
    a
}

/// Inner record-fields AAD: vault_id|record_id|key_epoch — 36 bytes.
/// Deliberately omits format_v: field sealing must stay stable across
/// reader-version bumps.
pub fn record_fields(
    vault_id: &[u8; VAULT_ID_LEN],
    record_id: &[u8; 16],
    key_epoch: u32,
) -> [u8; 36] {
    let mut a = [0u8; 36];
    a[0..16].copy_from_slice(vault_id);
    a[16..32].copy_from_slice(record_id);
    a[32..36].copy_from_slice(&key_epoch.to_le_bytes());
    a
}

/// Wrap-slot AAD: "mypassman/v1/wrap"|vault_id|key_epoch|slot_type.
/// Binding the vault + epoch stops a stale slot blob being spliced into a
/// rotated manifest (the old signature is exactly what rotation retires).
pub fn wrap_slot(vault_id: &[u8; VAULT_ID_LEN], key_epoch: u32, slot_type: u8) -> [u8; 38] {
    let mut a = [0u8; 38];
    a[..17].copy_from_slice(b"mypassman/v1/wrap");
    a[17..33].copy_from_slice(vault_id);
    a[33..37].copy_from_slice(&key_epoch.to_le_bytes());
    a[37] = slot_type;
    a
}

/// Preimage covered by a device signature: "mypassman/v1/opsig"|seq|nonce|ct.
pub fn op_sig_preimage(seq: u64, nonce: &[u8; 24], ct: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(18 + 8 + 24 + ct.len());
    p.extend_from_slice(b"mypassman/v1/opsig");
    p.extend_from_slice(&seq.to_le_bytes());
    p.extend_from_slice(nonce);
    p.extend_from_slice(ct);
    p
}
