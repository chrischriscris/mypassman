//! Op format (DESIGN.md §5). On-disk op:
//!   seq(8 LE) || nonce(24) || device_sig(64) || ct_len(4 LE) || ct
//!
//! `ct` = XChaCha20-Poly1305(k_ops) of the plaintext TLV, which contains
//! prev_op_hash, hlc, type, record_id, kind, schema_v, created, fields_ct,
//! gossip. `fields_ct` is itself nonce(24)||XChaCha20-Poly1305(k_rec, fields)
//! — record metadata is DEK-visible (needed for index/merge) while field
//! secrets sit behind the per-record key (decrypt-on-demand stays real).

use crate::aad;
use crate::error::{CoreError, Result};
use crate::item::{Item, ItemKind};
use crate::tlv::{self, Reader, Writer};
use crate::{DEVICE_ID_LEN, HASH_LEN, RECORD_ID_LEN, VAULT_ID_LEN};
use ed25519_dalek::Signature;
use mpm_crypto::aead::{self, NONCE_LEN};
use mpm_crypto::subkey;
use mpm_crypto::DeviceKey;

pub const OP_HEADER_LEN: usize = 8 + NONCE_LEN + 64 + 4;

// plaintext TLV tags
const T_PREV_HASH: u8 = 0x01;
const T_HLC: u8 = 0x02;
const T_TYPE: u8 = 0x03;
const T_RECORD_ID: u8 = 0x04;
const T_KIND: u8 = 0x05;
const T_SCHEMA_V: u8 = 0x06;
const T_CREATED: u8 = 0x07;
const T_FIELDS_CT: u8 = 0x08;
const T_GOSSIP: u8 = 0x09;
const T_NAME: u8 = 0x0A;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpType {
    Upsert = 1,
    Tombstone = 2,
    Meta = 3,
}

impl OpType {
    fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            1 => Self::Upsert,
            2 => Self::Tombstone,
            3 => Self::Meta,
            v => return Err(CoreError::BadOpType(v)),
        })
    }
}

/// One gossip observation: (device_id, seq, head_hash) — 56 bytes.
#[derive(Debug, Clone, Copy)]
pub struct Gossip {
    pub device_id: [u8; DEVICE_ID_LEN],
    pub seq: u64,
    pub head: [u8; HASH_LEN],
}

impl Gossip {
    pub const LEN: usize = DEVICE_ID_LEN + 8 + HASH_LEN;

    fn encode(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[..16].copy_from_slice(&self.device_id);
        b[16..24].copy_from_slice(&self.seq.to_le_bytes());
        b[24..56].copy_from_slice(&self.head);
        b
    }

    fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != Self::LEN {
            return Err(CoreError::Tlv("gossip entry"));
        }
        let mut g = Gossip {
            device_id: [0u8; 16],
            seq: u64::from_le_bytes(b[16..24].try_into().unwrap()),
            head: [0u8; 32],
        };
        g.device_id.copy_from_slice(&b[..16]);
        g.head.copy_from_slice(&b[24..56]);
        Ok(g)
    }
}

/// Decrypted op plaintext — record graph + display name visible to a
/// DEK-holder (needed for list/search without touching per-record keys),
/// secret fields still sealed behind k_rec.
#[derive(Debug, Clone)]
pub struct OpPlaintext {
    pub prev_op_hash: [u8; HASH_LEN],
    pub hlc: u64,
    pub op_type: OpType,
    pub record_id: [u8; RECORD_ID_LEN],
    pub kind: Option<ItemKind>,
    pub schema_v: u16,
    pub created: u64,
    pub name: Vec<u8>,      // index-visible display name (UTF-8)
    pub fields_ct: Vec<u8>, // nonce||inner_ct; empty for tombstone/meta
    pub gossip: Vec<Gossip>,
}

impl OpPlaintext {
    /// Decrypt the inner fields layer — the only place field plaintext exists.
    pub fn open_fields(&self, dek: &[u8; 32], vault_id: &[u8; VAULT_ID_LEN], key_epoch: u32) -> Result<Item> {
        if self.fields_ct.len() < NONCE_LEN + aead::TAG_LEN {
            return Err(CoreError::Tlv("fields_ct short"));
        }
        let (nonce, ct) = self.fields_ct.split_at(NONCE_LEN);
        let k_rec = subkey::derive_record_key(dek, &self.record_id);
        let pt = aead::open(&k_rec, nonce.try_into().unwrap(), &aad::record_fields(vault_id, &self.record_id, key_epoch), ct)?;
        Item::decode(&pt)
    }

    /// Seal a fields item into the inner layer.
    pub fn seal_fields(dek: &[u8; 32], vault_id: &[u8; VAULT_ID_LEN], key_epoch: u32, record_id: &[u8; 16], item: &Item) -> Result<Vec<u8>> {
        let k_rec = subkey::derive_record_key(dek, record_id);
        let nonce = aead::random_nonce();
        let ct = aead::seal(&k_rec, &nonce, &aad::record_fields(vault_id, record_id, key_epoch), &item.encode())?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.field(T_PREV_HASH, &self.prev_op_hash);
        w.u64f(T_HLC, self.hlc);
        w.u8f(T_TYPE, self.op_type as u8);
        w.field(T_RECORD_ID, &self.record_id);
        if let Some(k) = self.kind {
            w.u8f(T_KIND, k as u8);
        }
        w.u16f(T_SCHEMA_V, self.schema_v);
        w.u64f(T_CREATED, self.created);
        w.field(T_FIELDS_CT, &self.fields_ct);
        for g in &self.gossip {
            w.field(T_GOSSIP, &g.encode());
        }
        w.field(T_NAME, &self.name);
        Ok(w.finish())
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        let mut prev: Option<[u8; HASH_LEN]> = None;
        let mut hlc = None;
        let mut ty = None;
        let mut rid: Option<[u8; RECORD_ID_LEN]> = None;
        let mut kind = None;
        let mut schema_v = 0u16;
        let mut created = 0u64;
        let mut fields_ct = Vec::new();
        let mut gossip = Vec::new();
        let mut name = Vec::new();
        while let Some((t, v)) = r.next_field()? {
            match t {
                T_PREV_HASH => {
                    Reader::want_fixed(t, v, HASH_LEN)?;
                    prev = Some(v.try_into().unwrap());
                }
                T_HLC => hlc = Some(tlv::u64v(t, v)?),
                T_TYPE => ty = Some(OpType::from_u8(tlv::u8v(t, v)?)?),
                T_RECORD_ID => {
                    Reader::want_fixed(t, v, RECORD_ID_LEN)?;
                    rid = Some(v.try_into().unwrap());
                }
                T_KIND => kind = Some(ItemKind::from_u8(tlv::u8v(t, v)?)?),
                T_SCHEMA_V => schema_v = tlv::u16v(t, v)?,
                T_CREATED => created = tlv::u64v(t, v)?,
                T_FIELDS_CT => fields_ct = v.to_vec(),
                T_GOSSIP => gossip.push(Gossip::decode(v)?),
                T_NAME => name = v.to_vec(),
                _ => {} // forward-compatible: ignore unknown tags
            }
        }
        Ok(OpPlaintext {
            prev_op_hash: prev.ok_or(CoreError::Tlv("missing prev_op_hash"))?,
            hlc: hlc.ok_or(CoreError::Tlv("missing hlc"))?,
            op_type: ty.ok_or(CoreError::Tlv("missing type"))?,
            record_id: rid.ok_or(CoreError::Tlv("missing record_id"))?,
            kind,
            schema_v,
            created,
            name,
            fields_ct,
            gossip,
        })
    }
}

/// A stored op: header + ciphertext. Signature is over the canonical
/// preimage seq|nonce|ct (aad::op_sig_preimage).
#[derive(Debug, Clone)]
pub struct Op {
    pub seq: u64,
    pub nonce: [u8; NONCE_LEN],
    pub sig: [u8; 64],
    pub ct: Vec<u8>,
}

impl Op {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(OP_HEADER_LEN + self.ct.len());
        b.extend_from_slice(&self.seq.to_le_bytes());
        b.extend_from_slice(&self.nonce);
        b.extend_from_slice(&self.sig);
        b.extend_from_slice(&(self.ct.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.ct);
        b
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < OP_HEADER_LEN {
            return Err(CoreError::Tlv("op header"));
        }
        let seq = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let nonce: [u8; NONCE_LEN] = buf[8..8 + NONCE_LEN].try_into().unwrap();
        let sig: [u8; 64] = buf[8 + NONCE_LEN..8 + NONCE_LEN + 64].try_into().unwrap();
        let ct_len = u32::from_le_bytes(buf[OP_HEADER_LEN - 4..OP_HEADER_LEN].try_into().unwrap()) as usize;
        let end = OP_HEADER_LEN.checked_add(ct_len).ok_or(CoreError::Tlv("op len"))?;
        if end > buf.len() {
            return Err(CoreError::Tlv("op truncated"));
        }
        Ok((Op { seq, nonce, sig, ct: buf[OP_HEADER_LEN..end].to_vec() }, end))
    }

    pub fn hash(&self) -> [u8; HASH_LEN] {
        *blake3::hash(&self.encode()).as_bytes()
    }

    /// Verify device signature then open the outer layer.
    pub fn open(
        &self,
        device_vk: &[u8; 32],
        dek: &[u8; 32],
        vault_id: &[u8; VAULT_ID_LEN],
        key_epoch: u32,
        device_id: &[u8; DEVICE_ID_LEN],
    ) -> Result<OpPlaintext> {
        let sig = Signature::from_bytes(&self.sig);
        mpm_crypto::keys::verify(device_vk, &aad::op_sig_preimage(self.seq, &self.nonce, &self.ct), &sig)
            .map_err(|_| CoreError::BadOpSig(self.seq))?;
        let k_ops = subkey::derive_subkey(dek, subkey::CTX_OPS);
        let pt = aead::open(&k_ops, &self.nonce, &aad::op(vault_id, key_epoch, device_id, self.seq), &self.ct)?;
        OpPlaintext::decode(&pt)
    }

    /// Build, seal, and sign a new op.
    pub fn seal(
        pt: &OpPlaintext,
        seq: u64,
        dek: &[u8; 32],
        vault_id: &[u8; VAULT_ID_LEN],
        key_epoch: u32,
        device: &DeviceKey,
    ) -> Result<Self> {
        let k_ops = subkey::derive_subkey(dek, subkey::CTX_OPS);
        let nonce = aead::random_nonce();
        let ct = aead::seal(&k_ops, &nonce, &aad::op(vault_id, key_epoch, &device.id, seq), &pt.encode()?)?;
        let sig = device.sign(&aad::op_sig_preimage(seq, &nonce, &ct)).to_bytes();
        Ok(Op { seq, nonce, sig, ct })
    }
}
