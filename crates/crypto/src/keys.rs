use crate::{aead, CryptoError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const SIG_LEN: usize = 64;
pub const BUNDLE_LEN: usize = KEY_LEN * 2;

pub type SigningKeyBytes = [u8; KEY_LEN];
pub type VerifyingKeyBytes = [u8; KEY_LEN];

/// The vault's root secret: DEK + owner signing seed. Wrap slots each hold
/// an AEAD'd copy of this 64-byte bundle.
pub struct KeyBundle {
    pub dek: Zeroizing<[u8; KEY_LEN]>,
    owner_seed: Zeroizing<[u8; KEY_LEN]>,
}

impl KeyBundle {
    pub fn generate() -> Self {
        let mut dek = [0u8; KEY_LEN];
        let mut owner = [0u8; KEY_LEN];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut dek);
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut owner);
        Self { dek: Zeroizing::new(dek), owner_seed: Zeroizing::new(owner) }
    }

    pub fn owner_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.owner_seed)
    }

    pub fn owner_verifying_key(&self) -> VerifyingKeyBytes {
        self.owner_signing_key().verifying_key().to_bytes()
    }

    /// dek || owner_seed
    fn to_bytes(&self) -> Zeroizing<[u8; BUNDLE_LEN]> {
        let mut b = [0u8; BUNDLE_LEN];
        b[..KEY_LEN].copy_from_slice(&self.dek[..]);
        b[KEY_LEN..].copy_from_slice(&self.owner_seed[..]);
        Zeroizing::new(b)
    }

    fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != BUNDLE_LEN {
            return Err(CryptoError::BadKey);
        }
        let mut dek = [0u8; KEY_LEN];
        let mut owner = [0u8; KEY_LEN];
        dek.copy_from_slice(&b[..KEY_LEN]);
        owner.copy_from_slice(&b[KEY_LEN..]);
        Ok(Self { dek: Zeroizing::new(dek), owner_seed: Zeroizing::new(owner) })
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

    /// Unwrap a bundle blob produced by `wrap`.
    pub fn unwrap(kek: &[u8; KEY_LEN], aad: &[u8], blob: &[u8]) -> Result<Self> {
        if blob.len() < aead::NONCE_LEN + aead::TAG_LEN + BUNDLE_LEN {
            return Err(CryptoError::ShortInput);
        }
        let (nonce, ct) = blob.split_at(aead::NONCE_LEN);
        let pt = aead::open(kek, nonce.try_into().unwrap(), aad, ct)?;
        let bundle = Self::from_bytes(&pt)?;
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
        Self { seed: Zeroizing::new(seed), id }
    }

    pub fn from_bytes(seed: &[u8; KEY_LEN], id: [u8; 16]) -> Self {
        Self { seed: Zeroizing::new(*seed), id }
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
