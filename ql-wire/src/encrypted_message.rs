use bc_components::SymmetricKey;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use rkyv::{seal::Seal, vec::ArchivedVec, Archive, Deserialize, Serialize};

use crate::WireError;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce(pub [u8; Self::NONCE_SIZE]);

impl Nonce {
    pub const NONCE_SIZE: usize = 12;
}

pub const AUTH_SIZE: usize = 16;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage {
    ciphertext: Vec<u8>,
    nonce: Nonce,
    auth: [u8; AUTH_SIZE],
}

impl EncryptedMessage {
    pub fn encrypt(key: &SymmetricKey, mut plaintext: Vec<u8>, aad: &[u8], nonce: Nonce) -> Self {
        let cipher = ChaCha20Poly1305::new(key.data().into());
        let auth = cipher
            .encrypt_in_place_detached((&nonce.0).into(), aad, &mut plaintext)
            .expect("chacha20poly1305 encryption should succeed");
        Self {
            ciphertext: plaintext,
            nonce,
            auth: auth.into(),
        }
    }

    pub fn decrypt(&self, key: &SymmetricKey, aad: &[u8]) -> Result<Vec<u8>, WireError> {
        let cipher = ChaCha20Poly1305::new(key.data().into());
        let mut plaintext = self.ciphertext.clone();
        cipher
            .decrypt_in_place_detached(
                (&self.nonce.0).into(),
                aad,
                &mut plaintext,
                (&self.auth).into(),
            )
            .map_err(|_| WireError::InvalidPayload)?;
        Ok(plaintext)
    }
}

impl ArchivedEncryptedMessage {
    pub fn decrypt(&mut self, key: &SymmetricKey, aad: &[u8]) -> Result<&[u8], WireError> {
        let cipher = ChaCha20Poly1305::new(key.data().into());
        let nonce = &self.nonce;
        let auth = self.auth;
        let ciphertext = ArchivedVec::as_slice_seal(Seal::new(&mut self.ciphertext));
        let ciphertext = unsafe { ciphertext.unseal_unchecked() };
        cipher
            .decrypt_in_place_detached((&nonce.0).into(), aad, ciphertext, (&auth).into())
            .map_err(|_| WireError::InvalidPayload)?;
        Ok(ciphertext)
    }
}
