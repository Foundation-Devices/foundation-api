use libcrux_ml_kem::{mlkem1024, SHARED_SECRET_SIZE};

use crate::QlCrypto;

pub const ML_KEM_SUITE_TAG: &[u8] = b"ml-kem-1024";

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
pub struct MlKemPublicKey(Box<[u8; MlKemPublicKey::SIZE]>);

impl MlKemPublicKey {
    pub const SIZE: usize = mlkem1024::MlKem1024PublicKey::len();

    pub fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(Box::new(data))
    }

    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        self.0.as_ref()
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MlKemKeyPair {
    pub private: MlKemPrivateKey,
    pub public: MlKemPublicKey,
}

pub fn generate_ml_kem_keypair(crypto: &impl QlCrypto) -> MlKemKeyPair {
    crypto.mlkem_generate_keypair()
}
