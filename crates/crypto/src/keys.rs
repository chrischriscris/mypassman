use crate::{aead, CryptoError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const SIG_LEN: usize = 64;
pub const BUNDLE_LEN: usize = KEY_LEN * 2;

const BUNDLE_V2: u8 = 0x02;

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

    /// v2 wire: 0x02 || n(1) || (epoch u32 LE || dek 32)×n sorted || owner_seed(32)
    fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut b = Vec::with_capacity(2 + self.deks.len() * (4 + KEY_LEN) + KEY_LEN);
        b.push(BUNDLE_V2);
        b.push(self.deks.len() as u8);
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
        if b.len() < 2 + KEY_LEN || b[0] != BUNDLE_V2 {
            return Err(CryptoError::BadKey);
        }
        let n = b[1] as usize;
        let want = 2 + n * (4 + KEY_LEN) + KEY_LEN;
        if b.len() != want {
            return Err(CryptoError::BadKey);
        }
        let mut deks = std::collections::BTreeMap::new();
        let mut pos = 2;
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
