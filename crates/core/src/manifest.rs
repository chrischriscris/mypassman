//! MANIFEST — owner-signed, TLV-encoded (DESIGN.md §5).
//! File layout: owner_sig(64) || manifest_tlv.
//!
//! The signature proves "holder of owner_sign wrote this" — authenticity is
//! anchored at unlock: manifest.owner_vk MUST equal the unwrapped bundle's
//! owner verifying key, or we refuse to proceed.

use crate::error::{CoreError, Result};
use crate::tlv::{self, Reader, Writer};
use crate::{DEVICE_ID_LEN, FORMAT_VERSION, HASH_LEN, MIN_READER_VERSION, VAULT_ID_LEN};
use ed25519_dalek::{Signature, Signer};
use mpm_crypto::kdf::KdfParams;
use mpm_crypto::keys::SIG_LEN;

pub const SLOT_PASSWORD: u8 = 1;
pub const SLOT_RECOVERY: u8 = 2;
pub const SLOT_BIOMETRIC: u8 = 3; // marker only — bundle lives in OS keychain

// manifest tags
const T_VAULT_ID: u8 = 0x01;
const T_FORMAT_V: u8 = 0x02;
const T_MIN_READER: u8 = 0x03;
const T_KDF: u8 = 0x04;
const T_WRAP_SLOT: u8 = 0x05;
const T_KEY_EPOCH: u8 = 0x06;
const T_SNAPSHOT_EPOCH: u8 = 0x07;
const T_DEVICE: u8 = 0x08;
const T_PURGED_BEFORE: u8 = 0x09;
const T_OWNER_VK: u8 = 0x0A;

// wrap slot nested tags
const S_TYPE: u8 = 0x01;
const S_SALT: u8 = 0x02;
const S_M: u8 = 0x03;
const S_T: u8 = 0x04;
const S_P: u8 = 0x05;
const S_BLOB: u8 = 0x06;

// device entry nested tags
const D_ID: u8 = 0x01;
const D_VK: u8 = 0x02;
const D_NAME: u8 = 0x03;
const D_STATUS: u8 = 0x04; // 1 active, 2 tombstoned
const D_ENROLLED: u8 = 0x05;
const D_REVOKED_SEQ: u8 = 0x06; // trust horizon: ops with seq <= this still merge

const KDF_PACKED_LEN: usize = 44; // m|t|p|salt

#[derive(Debug, Clone)]
pub struct WrapSlot {
    pub slot_type: u8,
    pub kdf: Option<(KdfParams, [u8; 32])>, // params + salt; None for biometric markers
    pub blob: Vec<u8>,                      // nonce || AEAD(KeyBundle)
    /// Unrecognized nested fields, retained for lossless re-encode.
    pub extra: Vec<(u8, Vec<u8>)>,
}

#[derive(Debug, Clone)]
pub struct DeviceEntry {
    pub id: [u8; DEVICE_ID_LEN],
    pub vk: [u8; 32],
    pub name: String,
    pub active: bool,
    pub enrolled_at: u64,
    /// Revocation horizon: ops with seq <= this were written while the
    /// device was still trusted and keep merging after revocation; later
    /// seqs are rejected. `None` on an inactive device means "revoked
    /// before horizons existed" — nothing merges (strict).
    pub revoked_seq: Option<u64>,
    pub extra: Vec<(u8, Vec<u8>)>,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub vault_id: [u8; VAULT_ID_LEN],
    pub format_v: u16,
    pub min_reader_v: u16,
    pub kdf: KdfParams,
    pub kdf_salt: [u8; 32],
    pub wrap_slots: Vec<WrapSlot>,
    pub key_epoch: u32,
    pub snapshot_epoch: u64,
    pub devices: Vec<DeviceEntry>,
    pub purged_before_epoch: u64,
    pub owner_vk: [u8; 32],
    pub sig: [u8; SIG_LEN],
    /// Unrecognized top-level fields — re-emitted verbatim so re-signing a
    /// manifest written by a newer build doesn't silently delete data.
    pub extra: Vec<(u8, Vec<u8>)>,
}

impl Manifest {
    pub fn new(kdf: KdfParams, kdf_salt: [u8; 32], owner_vk: [u8; 32]) -> Self {
        let mut vault_id = [0u8; VAULT_ID_LEN];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut vault_id);
        Self {
            vault_id,
            format_v: FORMAT_VERSION,
            min_reader_v: MIN_READER_VERSION,
            kdf,
            kdf_salt,
            wrap_slots: Vec::new(),
            key_epoch: 1,
            snapshot_epoch: 0,
            devices: Vec::new(),
            purged_before_epoch: 0,
            owner_vk,
            sig: [0u8; SIG_LEN],
            extra: Vec::new(),
        }
    }

    pub fn device(&self, id: &[u8; DEVICE_ID_LEN]) -> Option<&DeviceEntry> {
        self.devices.iter().find(|d| &d.id == id)
    }

    /// Emit canonical TLV: all fields (known + retained extras) sorted by
    /// tag; repeated tags keep their relative order (stable sort).
    fn encode_body(&self) -> Vec<u8> {
        let mut f: Vec<(u8, Vec<u8>)> =
            Vec::with_capacity(10 + self.wrap_slots.len() + self.devices.len() + self.extra.len());
        f.push((T_VAULT_ID, self.vault_id.to_vec()));
        f.push((T_FORMAT_V, self.format_v.to_le_bytes().to_vec()));
        f.push((T_MIN_READER, self.min_reader_v.to_le_bytes().to_vec()));
        let mut kd = [0u8; KDF_PACKED_LEN];
        kd[0..4].copy_from_slice(&self.kdf.m_kib.to_le_bytes());
        kd[4..8].copy_from_slice(&self.kdf.t.to_le_bytes());
        kd[8..12].copy_from_slice(&self.kdf.p.to_le_bytes());
        kd[12..44].copy_from_slice(&self.kdf_salt);
        f.push((T_KDF, kd.to_vec()));
        for s in &self.wrap_slots {
            f.push((T_WRAP_SLOT, encode_slot(s)));
        }
        f.push((T_KEY_EPOCH, self.key_epoch.to_le_bytes().to_vec()));
        f.push((T_SNAPSHOT_EPOCH, self.snapshot_epoch.to_le_bytes().to_vec()));
        for d in &self.devices {
            f.push((T_DEVICE, encode_device(d)));
        }
        f.push((
            T_PURGED_BEFORE,
            self.purged_before_epoch.to_le_bytes().to_vec(),
        ));
        f.push((T_OWNER_VK, self.owner_vk.to_vec()));
        f.extend(self.extra.iter().cloned());
        f.sort_by_key(|(t, _)| *t);
        let mut w = Writer::new();
        for (t, v) in &f {
            w.field(*t, v);
        }
        w.finish()
    }

    /// Serialize + owner-sign → file bytes (sig || tlv).
    pub fn to_file(&mut self, owner: &ed25519_dalek::SigningKey) -> Vec<u8> {
        let body = self.encode_body();
        self.sig = owner.sign(&body).to_bytes();
        let mut out = Vec::with_capacity(SIG_LEN + body.len());
        out.extend_from_slice(&self.sig);
        out.extend_from_slice(&body);
        out
    }

    /// Parse file bytes; verifies the embedded self-signature. Caller MUST
    /// additionally check `manifest.owner_vk == bundle.owner_verifying_key()`
    /// after unlock.
    pub fn from_file(buf: &[u8]) -> Result<Self> {
        if buf.len() < SIG_LEN + 5 {
            return Err(CoreError::Tlv("manifest short"));
        }
        let sig: [u8; SIG_LEN] = buf[..SIG_LEN].try_into().unwrap();
        let body = &buf[SIG_LEN..];

        let mut m = Manifest {
            vault_id: [0u8; 16],
            format_v: 0,
            min_reader_v: 0,
            kdf: KdfParams::default(),
            kdf_salt: [0u8; 32],
            wrap_slots: Vec::new(),
            key_epoch: 0,
            snapshot_epoch: 0,
            devices: Vec::new(),
            purged_before_epoch: 0,
            owner_vk: [0u8; 32],
            sig,
            extra: Vec::new(),
        };

        let mut r = Reader::new(body);
        let mut ord = tlv::OrderGuard::default();
        let mut seen_vault_id = false;
        while let Some((t, v)) = r.next_field()? {
            ord.check(t, &[T_WRAP_SLOT, T_DEVICE])?;
            match t {
                T_VAULT_ID => {
                    Reader::want_fixed(t, v, VAULT_ID_LEN)?;
                    m.vault_id = v.try_into().unwrap();
                    seen_vault_id = true;
                }
                T_FORMAT_V => m.format_v = tlv::u16v(t, v)?,
                T_MIN_READER => m.min_reader_v = tlv::u16v(t, v)?,
                T_KDF => {
                    Reader::want_fixed(t, v, KDF_PACKED_LEN)?;
                    m.kdf = KdfParams {
                        m_kib: u32::from_le_bytes(v[0..4].try_into().unwrap()),
                        t: u32::from_le_bytes(v[4..8].try_into().unwrap()),
                        p: u32::from_le_bytes(v[8..12].try_into().unwrap()),
                    };
                    m.kdf_salt.copy_from_slice(&v[12..44]);
                }
                T_WRAP_SLOT => m.wrap_slots.push(parse_slot(v)?),
                T_KEY_EPOCH => m.key_epoch = tlv::u32v(t, v)?,
                T_SNAPSHOT_EPOCH => m.snapshot_epoch = tlv::u64v(t, v)?,
                T_DEVICE => m.devices.push(parse_device(v)?),
                T_PURGED_BEFORE => m.purged_before_epoch = tlv::u64v(t, v)?,
                T_OWNER_VK => {
                    Reader::want_fixed(t, v, 32)?;
                    m.owner_vk = v.try_into().unwrap();
                }
                _ => m.extra.push((t, v.to_vec())),
            }
        }

        if m.format_v > FORMAT_VERSION {
            return Err(CoreError::UnsupportedVersion(m.format_v));
        }
        // a manifest written by a newer format may carry semantics we'd
        // silently drop on re-sign — refuse rather than degrade it
        if m.min_reader_v > FORMAT_VERSION {
            return Err(CoreError::UnsupportedVersion(m.min_reader_v));
        }
        // vault_id is mandatory — the relay parser has always required it;
        // an absent one previously parsed as all-zeros (PROTO-01)
        if !seen_vault_id {
            return Err(CoreError::Tlv("vault_id"));
        }
        // Self-signature check: the embedded owner_vk must have signed body.
        let signature = Signature::from_bytes(&m.sig);
        mpm_crypto::keys::verify(&m.owner_vk, body, &signature)
            .map_err(|_| CoreError::BadManifestSig)?;
        Ok(m)
    }
}

fn encode_slot(s: &WrapSlot) -> Vec<u8> {
    let mut f: Vec<(u8, Vec<u8>)> = Vec::with_capacity(6 + s.extra.len());
    f.push((S_TYPE, vec![s.slot_type]));
    if let Some((p, salt)) = &s.kdf {
        f.push((S_SALT, salt.to_vec()));
        f.push((S_M, p.m_kib.to_le_bytes().to_vec()));
        f.push((S_T, p.t.to_le_bytes().to_vec()));
        f.push((S_P, p.p.to_le_bytes().to_vec()));
    }
    f.push((S_BLOB, s.blob.clone()));
    f.extend(s.extra.iter().cloned());
    f.sort_by_key(|(t, _)| *t);
    let mut w = Writer::new();
    for (t, v) in &f {
        w.field(*t, v);
    }
    w.finish()
}

fn parse_slot(buf: &[u8]) -> Result<WrapSlot> {
    let mut r = Reader::new(buf);
    let mut ord = tlv::OrderGuard::default();
    let mut slot_type = None;
    let mut salt: Option<[u8; 32]> = None;
    let (mut m, mut t_, mut p) = (0u32, 0u32, 0u32);
    let mut blob = Vec::new();
    let mut extra = Vec::new();
    while let Some((t, v)) = r.next_field()? {
        ord.check(t, &[])?;
        match t {
            S_TYPE => slot_type = Some(tlv::u8v(t, v)?),
            S_SALT => {
                Reader::want_fixed(t, v, 32)?;
                salt = Some(v.try_into().unwrap());
            }
            S_M => m = tlv::u32v(t, v)?,
            S_T => t_ = tlv::u32v(t, v)?,
            S_P => p = tlv::u32v(t, v)?,
            S_BLOB => blob = v.to_vec(),
            _ => extra.push((t, v.to_vec())),
        }
    }
    let slot_type = slot_type.ok_or(CoreError::Tlv("slot type"))?;
    if !matches!(slot_type, SLOT_PASSWORD | SLOT_RECOVERY | SLOT_BIOMETRIC) {
        return Err(CoreError::BadSlot(slot_type));
    }
    let kdf = salt.map(|s| (KdfParams { m_kib: m, t: t_, p }, s));
    Ok(WrapSlot {
        slot_type,
        kdf,
        blob,
        extra,
    })
}

fn encode_device(d: &DeviceEntry) -> Vec<u8> {
    let mut f: Vec<(u8, Vec<u8>)> = Vec::with_capacity(5 + d.extra.len());
    f.push((D_ID, d.id.to_vec()));
    f.push((D_VK, d.vk.to_vec()));
    f.push((D_NAME, d.name.as_bytes().to_vec()));
    f.push((D_STATUS, vec![if d.active { 1 } else { 2 }]));
    f.push((D_ENROLLED, d.enrolled_at.to_le_bytes().to_vec()));
    if let Some(rs) = d.revoked_seq {
        f.push((D_REVOKED_SEQ, rs.to_le_bytes().to_vec()));
    }
    f.extend(d.extra.iter().cloned());
    f.sort_by_key(|(t, _)| *t);
    let mut w = Writer::new();
    for (t, v) in &f {
        w.field(*t, v);
    }
    w.finish()
}

fn parse_device(buf: &[u8]) -> Result<DeviceEntry> {
    let mut r = Reader::new(buf);
    let mut ord = tlv::OrderGuard::default();
    let mut id = None;
    let mut vk = None;
    let mut name = String::new();
    let mut active = true;
    let mut enrolled = 0u64;
    let mut revoked_seq = None;
    let mut extra = Vec::new();
    while let Some((t, v)) = r.next_field()? {
        ord.check(t, &[])?;
        match t {
            D_ID => {
                Reader::want_fixed(t, v, DEVICE_ID_LEN)?;
                id = Some(v.try_into().unwrap());
            }
            D_VK => {
                Reader::want_fixed(t, v, 32)?;
                vk = Some(v.try_into().unwrap());
            }
            D_NAME => name = String::from_utf8_lossy(v).into_owned(),
            D_STATUS => active = tlv::u8v(t, v)? == 1,
            D_ENROLLED => enrolled = tlv::u64v(t, v)?,
            D_REVOKED_SEQ => revoked_seq = Some(tlv::u64v(t, v)?),
            _ => extra.push((t, v.to_vec())),
        }
    }
    Ok(DeviceEntry {
        id: id.ok_or(CoreError::Tlv("device id"))?,
        vk: vk.ok_or(CoreError::Tlv("device vk"))?,
        name,
        active,
        enrolled_at: enrolled,
        revoked_seq,
        extra,
    })
}

/// Garbage-in guard: is a 32-byte array plausibly a hash (used for
/// prev_op_hash zero-check on genesis ops).
pub fn is_zero_hash(h: &[u8; HASH_LEN]) -> bool {
    h.iter().all(|b| *b == 0)
}
