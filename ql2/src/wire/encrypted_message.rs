use bc_components::SymmetricKey;
use bc_rand::fill_random_data;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use rkyv::{seal::Seal, vec::ArchivedVec, Archive, Deserialize, Serialize};

use crate::QlError;

pub const NONCE_SIZE: usize = 12;
pub const AUTH_SIZE: usize = 16;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_SIZE],
    pub auth: [u8; AUTH_SIZE],
}

impl EncryptedMessage {
    pub fn new(ciphertext: Vec<u8>, nonce: [u8; NONCE_SIZE], auth: [u8; AUTH_SIZE]) -> Self {
        Self {
            ciphertext,
            nonce,
            auth,
        }
    }

    pub fn encrypt(key: &SymmetricKey, mut plaintext: Vec<u8>, aad: &[u8]) -> Self {
        let mut nonce = [0u8; NONCE_SIZE];
        fill_random_data(&mut nonce);
        let cipher = ChaCha20Poly1305::new(key.data().into());
        let auth = cipher
            .encrypt_in_place_detached((&nonce).into(), aad, &mut plaintext)
            .expect("chacha20poly1305 encryption should succeed");
        Self::new(plaintext, nonce, auth.into())
    }

    pub fn decrypt(&self, key: &SymmetricKey, aad: &[u8]) -> Result<Vec<u8>, QlError> {
        let cipher = ChaCha20Poly1305::new(key.data().into());
        let mut plaintext = self.ciphertext.clone();
        cipher
            .decrypt_in_place_detached(
                (&self.nonce).into(),
                aad,
                &mut plaintext,
                (&self.auth).into(),
            )
            .map_err(|_| QlError::InvalidPayload)?;
        Ok(plaintext)
    }
}

impl ArchivedEncryptedMessage {
    pub fn decrypt(&mut self, key: &SymmetricKey, aad: &[u8]) -> Result<&[u8], QlError> {
        let cipher = ChaCha20Poly1305::new(key.data().into());
        let nonce = self.nonce;
        let auth = self.auth;
        let ciphertext = ArchivedVec::as_slice_seal(Seal::new(&mut self.ciphertext));
        let ciphertext = unsafe { ciphertext.unseal_unchecked() };
        cipher
            .decrypt_in_place_detached((&nonce).into(), aad, ciphertext, (&auth).into())
            .map_err(|_| QlError::InvalidPayload)?;
        Ok(ciphertext)
    }
}
