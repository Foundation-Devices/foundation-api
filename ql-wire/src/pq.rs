use libcrux_ml_dsa::{ml_dsa_87, KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};
use libcrux_ml_kem::{mlkem1024, KEY_GENERATION_SEED_SIZE, SHARED_SECRET_SIZE};

use crate::QlCrypto;

pub(crate) const ML_KEM_SUITE_TAG: &[u8] = b"ml-kem-1024";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKey([u8; Self::SIZE]);

impl SessionKey {
    pub const SIZE: usize = SHARED_SECRET_SIZE;

    pub const fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(data)
    }

    pub const fn data(&self) -> &[u8; Self::SIZE] {
        &self.0
    }

    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for SessionKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

macro_rules! impl_byte_traits {
    ($name:ident) => {
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&self.as_bytes())
                    .finish()
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.as_bytes() == other.as_bytes()
            }
        }

        impl Eq for $name {}

        impl std::hash::Hash for $name {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.as_bytes().hash(state);
            }
        }
    };
}

#[derive(Clone)]
pub struct MlDsaPrivateKey(Box<ml_dsa_87::MLDSA87SigningKey>);

impl_byte_traits!(MlDsaPrivateKey);

impl MlDsaPrivateKey {
    pub const SIZE: usize = ml_dsa_87::MLDSA87SigningKey::len();

    pub fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(Box::new(ml_dsa_87::MLDSA87SigningKey::new(data)))
    }

    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        self.0.as_ref().as_ref()
    }

    pub fn sign(&self, crypto: &impl QlCrypto, message: &[u8]) -> MlDsaSignature {
        let mut randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
        crypto.fill_random_bytes(&mut randomness);
        // Safe: we always sign with the empty context, so the only remaining
        // error is libcrux's negligible-probability rejection-sampling failure.
        let signature = ml_dsa_87::sign(self.0.as_ref(), message, b"", randomness)
            .expect("ML-DSA signing should not fail");
        MlDsaSignature(Box::new(signature))
    }
}

#[derive(Clone)]
pub struct MlDsaPublicKey(Box<ml_dsa_87::MLDSA87VerificationKey>);

impl_byte_traits!(MlDsaPublicKey);

impl MlDsaPublicKey {
    pub const SIZE: usize = ml_dsa_87::MLDSA87VerificationKey::len();

    pub fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(Box::new(ml_dsa_87::MLDSA87VerificationKey::new(data)))
    }

    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        self.0.as_ref().as_ref()
    }

    pub fn verify(&self, signature: &MlDsaSignature, message: &[u8]) -> bool {
        ml_dsa_87::verify(self.0.as_ref(), message, b"", signature.0.as_ref()).is_ok()
    }

    pub fn verify_bytes(&self, signature: &[u8; MlDsaSignature::SIZE], message: &[u8]) -> bool {
        let signature = ml_dsa_87::MLDSA87Signature::new(*signature);
        ml_dsa_87::verify(self.0.as_ref(), message, b"", &signature).is_ok()
    }
}

#[derive(Clone)]
pub struct MlDsaSignature(Box<ml_dsa_87::MLDSA87Signature>);

impl_byte_traits!(MlDsaSignature);

impl MlDsaSignature {
    pub const SIZE: usize = ml_dsa_87::MLDSA87Signature::len();

    pub fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(Box::new(ml_dsa_87::MLDSA87Signature::new(data)))
    }

    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        ml_dsa_87::MLDSA87Signature::as_ref(self.0.as_ref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MlKemPublicKey(Box<[u8; MlKemPublicKey::SIZE]>);

impl MlKemPublicKey {
    pub const SIZE: usize = mlkem1024::MlKem1024PublicKey::len();

    pub fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(Box::new(data))
    }

    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        self.0.as_ref()
    }

    pub fn encapsulate_new_shared_secret(
        &self,
        crypto: &impl QlCrypto,
    ) -> (SessionKey, MlKemCiphertext) {
        let mut randomness = [0u8; SHARED_SECRET_SIZE];
        crypto.fill_random_bytes(&mut randomness);
        let public_key = mlkem1024::MlKem1024PublicKey::from(self.as_bytes());
        let (ciphertext, shared_secret) = mlkem1024::encapsulate(&public_key, randomness);
        (
            SessionKey::from_data(shared_secret),
            MlKemCiphertext::from_data(*ciphertext.as_slice()),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MlKemPrivateKey(Box<[u8; MlKemPrivateKey::SIZE]>);

impl MlKemPrivateKey {
    pub const SIZE: usize = mlkem1024::MlKem1024PrivateKey::len();

    pub fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(Box::new(data))
    }

    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        self.0.as_ref()
    }

    pub fn decapsulate_shared_secret(&self, ciphertext: &MlKemCiphertext) -> SessionKey {
        self.decapsulate_shared_secret_bytes(ciphertext.as_bytes())
    }

    pub fn decapsulate_shared_secret_bytes(
        &self,
        ciphertext: &[u8; MlKemCiphertext::SIZE],
    ) -> SessionKey {
        let private_key = mlkem1024::MlKem1024PrivateKey::from(self.as_bytes());
        let ciphertext = mlkem1024::MlKem1024Ciphertext::from(ciphertext);
        let shared_secret = mlkem1024::decapsulate(&private_key, &ciphertext);
        SessionKey::from_data(shared_secret)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MlKemCiphertext(Box<[u8; MlKemCiphertext::SIZE]>);

impl MlKemCiphertext {
    pub const SIZE: usize = mlkem1024::MlKem1024Ciphertext::len();

    pub fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(Box::new(data))
    }

    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        self.0.as_ref()
    }
}

pub fn generate_ml_dsa_keypair(crypto: &impl QlCrypto) -> (MlDsaPrivateKey, MlDsaPublicKey) {
    let mut randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
    crypto.fill_random_bytes(&mut randomness);
    let key_pair = ml_dsa_87::generate_key_pair(randomness);
    (
        MlDsaPrivateKey(Box::new(key_pair.signing_key)),
        MlDsaPublicKey(Box::new(key_pair.verification_key)),
    )
}

pub fn generate_ml_kem_keypair(crypto: &impl QlCrypto) -> (MlKemPrivateKey, MlKemPublicKey) {
    let mut randomness = [0u8; KEY_GENERATION_SEED_SIZE];
    crypto.fill_random_bytes(&mut randomness);
    let key_pair = mlkem1024::generate_key_pair(randomness);
    let (private_key, public_key) = key_pair.into_parts();
    (
        MlKemPrivateKey::from_data(*private_key.as_slice()),
        MlKemPublicKey::from_data(*public_key.as_slice()),
    )
}
