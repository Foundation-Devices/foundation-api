use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned};

use crate::{
    codec::{parse_mut, parse_ref, push_value},
    Nonce, QlCrypto, SessionKey, WireError,
};

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct EncryptedMessageWire {
    pub nonce: [u8; Nonce::SIZE],
    pub auth: [u8; EncryptedMessage::AUTH_SIZE],
    pub ciphertext: [u8],
}

pub type EncryptedMessageRef<'a> = Ref<&'a [u8], EncryptedMessageWire>;
pub type EncryptedMessageMut<'a> = Ref<&'a mut [u8], EncryptedMessageWire>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage {
    pub nonce: Nonce,
    pub auth: [u8; Self::AUTH_SIZE],
    pub ciphertext: Vec<u8>,
}

impl EncryptedMessageWire {
    pub fn parse(bytes: &[u8]) -> Result<EncryptedMessageRef<'_>, WireError> {
        parse_ref(bytes)
    }

    pub fn parse_mut(bytes: &mut [u8]) -> Result<EncryptedMessageMut<'_>, WireError> {
        parse_mut(bytes)
    }

    pub fn to_encrypted_message(&self) -> EncryptedMessage {
        EncryptedMessage {
            nonce: Nonce(self.nonce),
            auth: self.auth,
            ciphertext: self.ciphertext.to_vec(),
        }
    }

    pub fn decrypt<'a>(
        &'a mut self,
        crypto: &impl QlCrypto,
        key: &SessionKey,
        aad: &[u8],
    ) -> Result<&'a mut [u8], WireError> {
        let nonce = Nonce(self.nonce);
        if !crypto.decrypt_with_aead(key, &nonce, aad, &mut self.ciphertext, &self.auth) {
            return Err(WireError::DecryptFailed);
        }
        Ok(&mut self.ciphertext)
    }
}

impl EncryptedMessage {
    pub const AUTH_SIZE: usize = 16;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Nonce::SIZE + Self::AUTH_SIZE + self.ciphertext.len());
        self.encode_into(&mut out);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(EncryptedMessageWire::parse(bytes)?.to_encrypted_message())
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        push_value(
            out,
            &EncryptedMessageHeaderWire {
                nonce: self.nonce.0,
                auth: self.auth,
            },
        );
        out.extend_from_slice(&self.ciphertext);
    }

    pub fn encrypt(
        crypto: &impl QlCrypto,
        key: &SessionKey,
        mut plaintext: Vec<u8>,
        aad: &[u8],
        nonce: Nonce,
    ) -> Result<Self, WireError> {
        let auth = crypto
            .encrypt_with_aead(key, &nonce, aad, &mut plaintext)
            .ok_or(WireError::EncryptFailed)?;
        Ok(Self {
            nonce,
            auth,
            ciphertext: plaintext,
        })
    }

    pub fn decrypt(
        &self,
        crypto: &impl QlCrypto,
        key: &SessionKey,
        aad: &[u8],
    ) -> Result<Vec<u8>, WireError> {
        let mut plaintext = self.ciphertext.clone();
        if !crypto.decrypt_with_aead(key, &self.nonce, aad, &mut plaintext, &self.auth) {
            return Err(WireError::DecryptFailed);
        }
        Ok(plaintext)
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct EncryptedMessageHeaderWire {
    nonce: [u8; Nonce::SIZE],
    auth: [u8; EncryptedMessage::AUTH_SIZE],
}
