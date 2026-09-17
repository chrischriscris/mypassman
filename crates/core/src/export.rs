//! Portable export format (DESIGN.md §M2): a passphrase-sealed blob holding
//! every record's plaintext TLV. Independent of the vault's key hierarchy —
//! sealed by a one-shot export passphrase via Argon2id.
//!
//! Wire format:
//!   "MPMEXP" || fmt_v u8 || salt[32] || kdf m_kib u32le || t u32le || p u32le
//!          || nonce[24] || AEAD(kek, aad=header, pt=payload_tlv)
//! payload_tlv: repeated T_RECORD(0x01) whose value is a nested TLV:
//!   T_KIND(0x01) u8 | T_NAME(0x02) utf8 | T_FIELDS(0x03) item-tlv

use crate::error::{CoreError, Result};
use crate::item::ItemKind;
use crate::tlv::{OrderGuard, Reader, Writer};
use mpm_crypto::aead;
use mpm_crypto::kdf::{self, KdfParams};
use zeroize::Zeroizing;

const MAGIC: &[u8; 6] = b"MPMEXP";
const FMT_V: u8 = 1;
const T_RECORD: u8 = 0x01;
const T_KIND: u8 = 0x01;
const T_NAME: u8 = 0x02;
const T_FIELDS: u8 = 0x03;

/// One exported record: kind + name + the item's canonical field TLV.
pub struct ExportRecord {
    pub kind: ItemKind,
    pub name: String,
    pub fields: Zeroizing<Vec<u8>>, // Item::encode() output
}

/// Seal `records` under `passphrase`. Returns the portable blob.
pub fn seal_export(records: &[ExportRecord], passphrase: &[u8]) -> Result<Vec<u8>> {
    let mut payload = Writer::new();
    for r in records {
        let mut inner = Writer::new();
        inner.field(T_KIND, &[r.kind as u8]);
        inner.field(T_NAME, r.name.as_bytes());
        inner.field(T_FIELDS, &r.fields);
        payload.field(T_RECORD, &inner.finish());
    }
    let pt = Zeroizing::new(payload.finish());

    let mut salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut salt);
    let params = KdfParams::default();
    let kek = Zeroizing::new(kdf::derive_kek(passphrase, &salt, &params)?);

    let mut header = Vec::with_capacity(6 + 1 + 32 + 12);
    header.extend_from_slice(MAGIC);
    header.push(FMT_V);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&params.m_kib.to_le_bytes());
    header.extend_from_slice(&params.t.to_le_bytes());
    header.extend_from_slice(&params.p.to_le_bytes());

    let mut nonce = [0u8; 24];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
    let ct = aead::seal(&kek, &nonce, &header, &pt)?;
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&ct);
    Ok(header)
}

/// Open a sealed export blob. Header params are bounds-checked before the
/// Argon2 run (hostile file → bounded allocation).
pub fn open_export(blob: &[u8], passphrase: &[u8]) -> Result<Vec<ExportRecord>> {
    if blob.len() < 6 + 1 + 32 + 12 + 24 + 16 || &blob[..6] != MAGIC {
        return Err(CoreError::Corrupt("not an MPMEXP blob".into()));
    }
    if blob[6] != FMT_V {
        return Err(CoreError::Corrupt(format!(
            "export format v{} > reader v{FMT_V}",
            blob[6]
        )));
    }
    let header_len = 6 + 1 + 32 + 12;
    let header = &blob[..header_len];
    let salt: &[u8; 32] = blob[7..39].try_into().unwrap();
    let params = KdfParams {
        m_kib: u32::from_le_bytes(blob[39..43].try_into().unwrap()),
        t: u32::from_le_bytes(blob[43..47].try_into().unwrap()),
        p: u32::from_le_bytes(blob[47..51].try_into().unwrap()),
    };
    params
        .check_bounds(KDF_EXPORT_CAP_KIB)
        .map_err(|_| CoreError::Corrupt("export kdf params out of bounds".into()))?;
    let nonce: &[u8; 24] = blob[header_len..header_len + 24].try_into().unwrap();
    let ct = &blob[header_len + 24..];

    let kek = Zeroizing::new(kdf::derive_kek(passphrase, salt, &params)?);
    let pt = Zeroizing::new(
        aead::open(&kek, nonce, header, ct).map_err(|_| CoreError::BadExportPassphrase)?,
    );

    let mut out = Vec::new();
    let mut r = Reader::new(&pt);
    let mut ord = OrderGuard::default();
    while let Some((t, v)) = r.next_field()? {
        ord.check(t, &[T_RECORD])?;
        if t != T_RECORD {
            continue; // forward-compat: skip unknown top-level fields
        }
        let mut kind = None;
        let mut name = None;
        let mut fields = None;
        let mut ir = Reader::new(v);
        let mut iord = OrderGuard::default();
        while let Some((it, iv)) = ir.next_field()? {
            iord.check(it, &[])?;
            match it {
                T_KIND => kind = Some(ItemKind::from_u8(iv.first().copied().unwrap_or(0))?),
                T_NAME => {
                    name = Some(
                        std::str::from_utf8(iv)
                            .map_err(|_| CoreError::Corrupt("export name not utf8".into()))?
                            .to_owned(),
                    )
                }
                T_FIELDS => fields = Some(Zeroizing::new(iv.to_vec())),
                _ => {}
            }
        }
        let (Some(kind), Some(name), Some(fields)) = (kind, name, fields) else {
            return Err(CoreError::Corrupt("export record missing fields".into()));
        };
        out.push(ExportRecord { kind, name, fields });
    }
    Ok(out)
}

/// Export files are attacker-controlled: cap Argon2 below the vault ceiling.
const KDF_EXPORT_CAP_KIB: u32 = 262_144;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{tag, Item};

    fn rec(name: &str) -> ExportRecord {
        let mut it = Item::default();
        it.set(tag::NAME, name.as_bytes().to_vec());
        it.set(tag::USERNAME, b"u".to_vec());
        it.set(tag::PASSWORD, b"hunter2".to_vec());
        ExportRecord {
            kind: ItemKind::Login,
            name: name.into(),
            fields: Zeroizing::new(it.encode()),
        }
    }

    #[test]
    fn export_roundtrip() {
        let blob = seal_export(&[rec("a"), rec("b")], b"pw").unwrap();
        let got = open_export(&blob, b"pw").unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, "a");
        let it = Item::decode(&got[0].fields).unwrap();
        assert_eq!(it.get_str(tag::PASSWORD), Some("hunter2"));
    }

    #[test]
    fn wrong_passphrase_and_tamper() {
        let blob = seal_export(&[rec("a")], b"pw").unwrap();
        assert!(open_export(&blob, b"nope").is_err());
        let mut bad = blob.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(open_export(&bad, b"pw").is_err());
        // hostile kdf params: 4 GiB memory request → rejected pre-alloc
        let mut evil = blob.clone();
        evil[39..43].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(open_export(&evil, b"pw").is_err());
    }
}
