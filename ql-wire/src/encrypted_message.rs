use zerocopy::{
    byte_slice::{ByteSlice, ByteSliceMut},
    FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned,
};

use crate::{
    codec::{parse, push_value},
    Nonce, QlCrypto, SessionKey, WireError,
};

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct EncryptedMessageWire {
    pub nonce: [u8; Nonce::SIZE],
    pub auth: [u8; EncryptedMessage::AUTH_SIZE],
    pub ciphertext: [u8],
}

pub struct EncryptedMessageRef<B> {
    wire: Ref<B, EncryptedMessageWire>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage {
    pub nonce: Nonce,
    pub auth: [u8; Self::AUTH_SIZE],
    pub ciphertext: Vec<u8>,
}

impl<B: ByteSlice> EncryptedMessageRef<B> {
    pub fn parse(bytes: B) -> Result<Self, WireError> {
        Ok(Self {
            wire: parse(bytes)?,
        })
    }

    pub fn nonce(&self) -> Nonce {
        Nonce(self.wire.nonce)
    }

    pub fn auth(&self) -> &[u8; EncryptedMessage::AUTH_SIZE] {
        &self.wire.auth
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.wire.ciphertext
    }

    pub fn to_encrypted_message(&self) -> EncryptedMessage {
        EncryptedMessage {
            nonce: self.nonce(),
            auth: *self.auth(),
            ciphertext: self.ciphertext().to_vec(),
        }
    }
}

impl<B: ByteSliceMut> EncryptedMessageRef<B> {
    pub fn ciphertext_mut(&mut self) -> &mut [u8] {
        &mut self.wire.ciphertext
    }

    pub fn decrypt<'a>(
        &'a mut self,
        crypto: &impl QlCrypto,
        key: &SessionKey,
        aad: &[u8],
    ) -> Result<&'a mut [u8], WireError> {
        let nonce = self.nonce();
        let auth = self.wire.auth;
        if !crypto.decrypt_with_aead(key, &nonce, aad, &mut self.wire.ciphertext, &auth) {
            return Err(WireError::DecryptFailed);
        }
        Ok(&mut self.wire.ciphertext)
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
        Ok(EncryptedMessageRef::parse(bytes)?.to_encrypted_message())
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
