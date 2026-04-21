use crate::{
    MlKemCiphertext, MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey, Nonce, SessionKey,
    ENCRYPTED_MESSAGE_AUTH_SIZE,
};

pub trait QlRandom {
    fn fill_random_bytes(&self, out: &mut [u8]);
}

pub trait QlHash {
    fn sha256(&self, parts: &[&[u8]]) -> [u8; 32];
}

pub trait QlAead {
    fn aes256_gcm_encrypt(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> [u8; ENCRYPTED_MESSAGE_AUTH_SIZE];

    fn aes256_gcm_decrypt(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
        auth_tag: &[u8; ENCRYPTED_MESSAGE_AUTH_SIZE],
    ) -> bool;
}

pub trait QlKem {
    fn mlkem_generate_keypair(&self) -> MlKemKeyPair;

    fn mlkem_encapsulate(&self, public_key: &MlKemPublicKey) -> (MlKemCiphertext, SessionKey);

    fn mlkem_decapsulate(
        &self,
        private_key: &MlKemPrivateKey,
        ciphertext: &MlKemCiphertext,
    ) -> SessionKey;
}

pub trait QlCrypto: QlRandom + QlHash + QlAead + QlKem {}

impl<T> QlCrypto for T where T: QlRandom + QlHash + QlAead + QlKem {}
