use crate::{aead, CryptoError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const SIG_LEN: usize = 64;
pub const BUNDLE_LEN: usize = KEY_LEN * 2;

const BUNDLE_V2: u8 = 0x02;
const BUNDLE_V3: u8 = 0x03;

pub type SigningKeyBytes = [u8; KEY_LEN];
pub type VerifyingKeyBytes = [u8; KEY_LEN];

/// The vault's root secret: DEK history + owner signing seed.
///
/// Ops bind `key_epoch` in their AAD; after a rotation old ops need their
/// epoch's DEK while new writes use the current (max) one — so the bundle
/// carries the whole map. Wrap slots AEAD the serialized map; a joining
/// device gets full history in one unwrap. A revoked device keeps only the
/// DEKs it already saw — that's exactly what rotation protects.
pub struct KeyBundle {
    deks: std::collections::BTreeMap<u32, Zeroizing<[u8; KEY_LEN]>>,
    owner_seed: Zeroizing<[u8; KEY_LEN]>,
}

impl KeyBundle {
    pub fn generate() -> Self {
        let mut dek = [0u8; KEY_LEN];
        let mut owner = [0u8; KEY_LEN];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut dek);
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut owner);
        let mut deks = std::collections::BTreeMap::new();
        deks.insert(1, Zeroizing::new(dek));
        Self {
            deks,
            owner_seed: Zeroizing::new(owner),
        }
    }

    /// DEK of the current (highest) epoch — used for all new writes.
    pub fn dek(&self) -> &[u8; KEY_LEN] {
        self.deks
            .values()
            .next_back()
            .map(|d| &**d)
            .unwrap_or(&[0u8; KEY_LEN])
    }

    /// DEK for a specific epoch — ops sealed before a rotation open under
    /// their own epoch's key.
    pub fn dek_at(&self, epoch: u32) -> Option<&[u8; KEY_LEN]> {
        self.deks.get(&epoch).map(|d| &**d)
    }

    pub fn current_epoch(&self) -> u32 {
        self.deks.keys().next_back().copied().unwrap_or(0)
    }

    /// Epochs we hold, newest first — open-fallback order.
    pub fn epochs_desc(&self) -> impl Iterator<Item = u32> + '_ {
        self.deks.keys().rev().copied()
    }

    /// Rotate: mint a fresh DEK at `current+1`. Old epochs are retained so
    /// existing ops stay decryptable; new writes move to the new epoch.
    pub fn rotate(&mut self) -> u32 {
        let epoch = self.current_epoch() + 1;
        let mut dek = [0u8; KEY_LEN];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut dek);
        self.deks.insert(epoch, Zeroizing::new(dek));
        epoch
    }

    pub fn owner_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.owner_seed)
    }

    pub fn owner_verifying_key(&self) -> VerifyingKeyBytes {
        self.owner_signing_key().verifying_key().to_bytes()
    }

    /// v2 wire: 0x02 || n(u8) || (epoch u32 LE || dek 32)×n sorted || owner_seed(32)
    /// v3 wire: 0x03 || n(u32 LE) || (epoch u32 LE || dek 32)×n sorted || owner_seed(32)
    ///
    /// v2's u8 count overflows at 256 DEKs — past that the bundle switches to
    /// v3. Old binaries decode everything ≤255 exactly as before, so a bundle
    /// only becomes version-exclusive at the count that would have locked the
    /// old reader out anyway (CRYPTO-01).
    fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let v2 = self.deks.len() <= u8::MAX as usize;
        let mut b =
            Vec::with_capacity(if v2 { 2 } else { 5 } + self.deks.len() * (4 + KEY_LEN) + KEY_LEN);
        if v2 {
            b.push(BUNDLE_V2);
            b.push(self.deks.len() as u8);
        } else {
            b.push(BUNDLE_V3);
            b.extend_from_slice(&(self.deks.len() as u32).to_le_bytes());
        }
        for (epoch, dek) in &self.deks {
            b.extend_from_slice(&epoch.to_le_bytes());
            b.extend_from_slice(&dek[..]);
        }
        b.extend_from_slice(&self.owner_seed[..]);
        Zeroizing::new(b)
    }

    /// `epoch_hint` names the epoch a *legacy* (v1, 64-byte) bundle was
    /// wrapped under — its DEK is that epoch's by definition.
    fn from_bytes(b: &[u8], epoch_hint: u32) -> Result<Self> {
        if b.len() == BUNDLE_LEN {
            let mut dek = [0u8; KEY_LEN];
            let mut owner = [0u8; KEY_LEN];
            dek.copy_from_slice(&b[..KEY_LEN]);
            owner.copy_from_slice(&b[KEY_LEN..]);
            let mut deks = std::collections::BTreeMap::new();
            deks.insert(epoch_hint, Zeroizing::new(dek));
            return Ok(Self {
                deks,
                owner_seed: Zeroizing::new(owner),
            });
        }
        if b.len() < 2 + KEY_LEN {
            return Err(CryptoError::BadKey);
        }
        let (n, mut pos) = match b[0] {
            BUNDLE_V2 => (b[1] as usize, 2usize),
            BUNDLE_V3 => {
                if b.len() < 5 + KEY_LEN {
                    return Err(CryptoError::BadKey);
                }
                (
                    u32::from_le_bytes(b[1..5].try_into().unwrap()) as usize,
                    5usize,
                )
            }
            _ => return Err(CryptoError::BadKey),
        };
        let want = pos + n * (4 + KEY_LEN) + KEY_LEN;
        if b.len() != want {
            return Err(CryptoError::BadKey);
        }
        let mut deks = std::collections::BTreeMap::new();
        for _ in 0..n {
            let epoch = u32::from_le_bytes(b[pos..pos + 4].try_into().unwrap());
            let mut dek = [0u8; KEY_LEN];
            dek.copy_from_slice(&b[pos + 4..pos + 4 + KEY_LEN]);
            deks.insert(epoch, Zeroizing::new(dek));
            pos += 4 + KEY_LEN;
        }
        if deks.is_empty() {
            return Err(CryptoError::BadKey);
        }
        let mut owner = [0u8; KEY_LEN];
        owner.copy_from_slice(&b[pos..pos + KEY_LEN]);
        Ok(Self {
            deks,
            owner_seed: Zeroizing::new(owner),
        })
    }

    /// Wrap the bundle under a KEK. Output = nonce(24) || ciphertext.
    pub fn wrap(&self, kek: &[u8; KEY_LEN], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce = aead::random_nonce();
        let ct = aead::seal(kek, &nonce, aad, &self.to_bytes()[..])?;
        let mut out = Vec::with_capacity(aead::NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Unwrap a bundle blob produced by `wrap`. `aad_epoch` is the
    /// key_epoch baked into `aad` — legacy 64-byte bundles register their
    /// DEK under it.
    pub fn unwrap(kek: &[u8; KEY_LEN], aad: &[u8], blob: &[u8], aad_epoch: u32) -> Result<Self> {
        if blob.len() < aead::NONCE_LEN + aead::TAG_LEN + BUNDLE_LEN {
            return Err(CryptoError::ShortInput);
        }
        let (nonce, ct) = blob.split_at(aead::NONCE_LEN);
        let pt = aead::open(kek, nonce.try_into().unwrap(), aad, ct)?;
        let bundle = Self::from_bytes(&pt, aad_epoch)?;
        Zeroizing::new(pt); // drop copy
        Ok(bundle)
    }
}

/// A per-device signing identity. The private half lives ONLY on the device
/// (never inside the synced vault dir); the pubkey goes in the registry.
pub struct DeviceKey {
    seed: Zeroizing<[u8; KEY_LEN]>,
    pub id: [u8; 16],
}

impl DeviceKey {
    pub fn generate() -> Self {
        let mut seed = [0u8; KEY_LEN];
        let mut id = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
        Self {
            seed: Zeroizing::new(seed),
            id,
        }
    }

    pub fn from_bytes(seed: &[u8; KEY_LEN], id: [u8; 16]) -> Self {
        Self {
            seed: Zeroizing::new(*seed),
            id,
        }
    }

    pub fn seed_bytes(&self) -> &[u8; KEY_LEN] {
        &self.seed
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }

    pub fn verifying_key(&self) -> VerifyingKeyBytes {
        self.signing_key().verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key().sign(msg)
    }
}

pub fn verify(vk_bytes: &VerifyingKeyBytes, msg: &[u8], sig: &Signature) -> Result<()> {
    let vk = VerifyingKey::from_bytes(vk_bytes).map_err(|_| CryptoError::BadKey)?;
    vk.verify(msg, sig).map_err(|_| CryptoError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(bundle: &KeyBundle, aad_epoch: u32) -> KeyBundle {
        let kek = [7u8; KEY_LEN];
        let aad = b"test-aad";
        let blob = bundle.wrap(&kek, aad).unwrap();
        KeyBundle::unwrap(&kek, aad, &blob, aad_epoch).unwrap()
    }

    #[test]
    fn bundle_v2_roundtrip() {
        let b = roundtrip(&KeyBundle::generate(), 1);
        assert_eq!(b.current_epoch(), 1);
    }

    /// v1 (64-byte) bundles must still decode — their DEK registers under
    /// the wrap slot's epoch hint.
    #[test]
    fn bundle_v1_decodes_under_epoch_hint() {
        let mut raw = [0u8; BUNDLE_LEN];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut raw);
        // v1 has no version byte — raw key material may collide with one
        raw[0] = BUNDLE_V2;
        let b = KeyBundle::from_bytes(&raw, 42).unwrap();
        assert_eq!(b.current_epoch(), 42);
        assert_eq!(b.dek_at(42).unwrap(), &raw[..KEY_LEN]);
        assert!(b.dek_at(1).is_none());
    }

    /// CRYPTO-01: a bundle with ≤255 DEKs stays on the v2 wire — old
    /// binaries keep reading bundles in the range they could always read.
    #[test]
    fn bundle_255_deks_stays_v2() {
        let mut b = KeyBundle::generate();
        for _ in 1..255 {
            b.rotate();
        }
        assert_eq!(b.current_epoch(), 255);
        let bytes = b.to_bytes();
        assert_eq!(bytes[0], BUNDLE_V2);
        let back = roundtrip(&b, 255);
        assert_eq!(back.current_epoch(), 255);
        assert!(back.dek_at(1).is_some());
    }

    /// CRYPTO-01: the 256th DEK overflowed v2's u8 count → unwrap failed and
    /// every replica locked out. v3 carries the full history.
    #[test]
    fn bundle_256_deks_switches_to_v3() {
        let mut b = KeyBundle::generate();
        for _ in 1..300 {
            b.rotate();
        }
        assert_eq!(b.current_epoch(), 300);
        let bytes = b.to_bytes();
        assert_eq!(bytes[0], BUNDLE_V3);
        let back = roundtrip(&b, 300);
        assert_eq!(back.current_epoch(), 300);
        // every old ciphertext stays decryptable — nothing is dropped
        for e in 1..=300 {
            assert!(back.dek_at(e).is_some(), "epoch {e} lost");
        }
    }

    #[test]
    fn bundle_v3_rejects_truncation() {
        let mut b = KeyBundle::generate();
        for _ in 1..256 {
            b.rotate();
        }
        let mut bytes = b.to_bytes().to_vec();
        bytes.pop();
        assert!(KeyBundle::from_bytes(&bytes, 1).is_err());
    }
}
