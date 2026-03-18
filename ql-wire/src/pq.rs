use libcrux_ml_dsa::{ml_dsa_87, KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};
use libcrux_ml_kem::{mlkem1024, KEY_GENERATION_SEED_SIZE, SHARED_SECRET_SIZE};

use crate::{QlCrypto, WireError};

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MlDsaPrivateKey([u8; MlDsaPrivateKey::SIZE]);

impl MlDsaPrivateKey {
    pub const SIZE: usize = ml_dsa_87::MLDSA87SigningKey::len();

    pub const fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(data)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }

    pub fn sign(
        &self,
        crypto: &impl QlCrypto,
        message: &[u8],
    ) -> Result<MlDsaSignature, WireError> {
        let mut randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
        crypto.fill_random_bytes(&mut randomness);
        let signing_key = ml_dsa_87::MLDSA87SigningKey::new(self.0);
        let signature = ml_dsa_87::sign(&signing_key, message, b"", randomness)
            .map_err(|_| WireError::SigningFailed)?;
        Ok(MlDsaSignature::from_data(*signature.as_ref()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MlDsaPublicKey([u8; MlDsaPublicKey::SIZE]);

impl MlDsaPublicKey {
    pub const SIZE: usize = ml_dsa_87::MLDSA87VerificationKey::len();

    pub const fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(data)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }

    pub fn verify(&self, signature: &MlDsaSignature, message: &[u8]) -> bool {
        let verification_key = ml_dsa_87::MLDSA87VerificationKey::new(self.0);
        let signature = ml_dsa_87::MLDSA87Signature::new(*signature.as_bytes());
        ml_dsa_87::verify(&verification_key, message, b"", &signature).is_ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MlDsaSignature([u8; MlDsaSignature::SIZE]);

impl MlDsaSignature {
    pub const SIZE: usize = ml_dsa_87::MLDSA87Signature::len();

    pub const fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(data)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MlKemPublicKey([u8; MlKemPublicKey::SIZE]);

impl MlKemPublicKey {
    pub const SIZE: usize = mlkem1024::MlKem1024PublicKey::len();

    pub const fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(data)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }

    pub fn encapsulate_new_shared_secret(
        &self,
        crypto: &impl QlCrypto,
    ) -> Result<(SessionKey, MlKemCiphertext), WireError> {
        let mut randomness = [0u8; SHARED_SECRET_SIZE];
        crypto.fill_random_bytes(&mut randomness);
        let public_key = mlkem1024::MlKem1024PublicKey::from(self.as_bytes());
        let (ciphertext, shared_secret) = mlkem1024::encapsulate(&public_key, randomness);
        Ok((
            SessionKey::from_data(shared_secret),
            MlKemCiphertext::from_data(*ciphertext.as_slice()),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MlKemPrivateKey([u8; MlKemPrivateKey::SIZE]);

impl MlKemPrivateKey {
    pub const SIZE: usize = mlkem1024::MlKem1024PrivateKey::len();

    pub const fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(data)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }

    pub fn decapsulate_shared_secret(
        &self,
        ciphertext: &MlKemCiphertext,
    ) -> Result<SessionKey, WireError> {
        let private_key = mlkem1024::MlKem1024PrivateKey::from(self.as_bytes());
        let ciphertext = mlkem1024::MlKem1024Ciphertext::from(ciphertext.as_bytes());
        let shared_secret = mlkem1024::decapsulate(&private_key, &ciphertext);
        Ok(SessionKey::from_data(shared_secret))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MlKemCiphertext([u8; MlKemCiphertext::SIZE]);

impl MlKemCiphertext {
    pub const SIZE: usize = mlkem1024::MlKem1024Ciphertext::len();

    pub const fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(data)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }
}

pub fn generate_ml_dsa_keypair(crypto: &impl QlCrypto) -> (MlDsaPrivateKey, MlDsaPublicKey) {
    let mut randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
    crypto.fill_random_bytes(&mut randomness);
    let key_pair = ml_dsa_87::generate_key_pair(randomness);
    (
        MlDsaPrivateKey::from_data(*key_pair.signing_key.as_ref()),
        MlDsaPublicKey::from_data(*key_pair.verification_key.as_ref()),
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
