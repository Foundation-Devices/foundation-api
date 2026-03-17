use bc_components::SymmetricKey;
use rkyv::{seal::Seal, vec::ArchivedVec, Archive, Deserialize, Serialize};

use crate::{QlCrypto, WireError};

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
    pub fn encrypt(
        crypto: &impl QlCrypto,
        key: &SymmetricKey,
        mut plaintext: Vec<u8>,
        aad: &[u8],
        nonce: Nonce,
    ) -> Result<Self, WireError> {
        let auth = crypto
            .encrypt_with_aead(key, &nonce, aad, &mut plaintext)
            .ok_or(WireError::EncryptFailed)?;
        Ok(Self {
            ciphertext: plaintext,
            nonce,
            auth,
        })
    }

    pub fn decrypt(
        &self,
        crypto: &impl QlCrypto,
        key: &SymmetricKey,
        aad: &[u8],
    ) -> Result<Vec<u8>, WireError> {
        let mut plaintext = self.ciphertext.clone();
        if !crypto.decrypt_with_aead(key, &self.nonce, aad, &mut plaintext, &self.auth) {
            return Err(WireError::DecryptFailed);
        }
        Ok(plaintext)
    }
}

impl ArchivedEncryptedMessage {
    pub fn decrypt(
        &mut self,
        crypto: &impl QlCrypto,
        key: &SymmetricKey,
        aad: &[u8],
    ) -> Result<&[u8], WireError> {
        let nonce = Nonce(self.nonce.0);
        let auth = self.auth;
        let ciphertext = ArchivedVec::as_slice_seal(Seal::new(&mut self.ciphertext));
        let ciphertext = unsafe { ciphertext.unseal_unchecked() };
        if !crypto.decrypt_with_aead(key, &nonce, aad, ciphertext, &auth) {
            return Err(WireError::DecryptFailed);
        }
        Ok(ciphertext)
    }
}
