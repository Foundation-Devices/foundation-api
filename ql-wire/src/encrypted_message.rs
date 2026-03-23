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
pub struct EncryptedMessageWire {
    pub nonce: [u8; Nonce::SIZE],
    pub auth: [u8; EncryptedMessage::AUTH_SIZE],
    pub ciphertext: [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage {
    pub nonce: Nonce,
    pub auth: [u8; Self::AUTH_SIZE],
    pub ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    pub const AUTH_SIZE: usize = 16;

    pub fn parse<B: ByteSlice>(bytes: B) -> Result<Ref<B, EncryptedMessageWire>, WireError> {
        parse(bytes)
    }

    pub fn from_wire(wire: &EncryptedMessageWire) -> Self {
        Self {
            nonce: Nonce(wire.nonce),
            auth: wire.auth,
            ciphertext: wire.ciphertext.to_vec(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Nonce::SIZE + Self::AUTH_SIZE + self.ciphertext.len());
        self.encode_into(&mut out);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(Self::from_wire(&Self::parse(bytes)?))
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
    ) -> Self {
        let auth = crypto.encrypt_with_aead(key, &nonce, aad, &mut plaintext);
        Self {
            nonce,
            auth,
            ciphertext: plaintext,
        }
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

    pub fn decrypt_in_place<'a, B: ByteSliceMut>(
        wire: &'a mut Ref<B, EncryptedMessageWire>,
        crypto: &impl QlCrypto,
        key: &SessionKey,
        aad: &[u8],
    ) -> Result<&'a mut [u8], WireError> {
        let nonce = Nonce(wire.nonce);
        let auth = wire.auth;
        if !crypto.decrypt_with_aead(key, &nonce, aad, &mut wire.ciphertext, &auth) {
            return Err(WireError::DecryptFailed);
        }
        Ok(&mut wire.ciphertext)
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct EncryptedMessageHeaderWire {
    pub nonce: [u8; Nonce::SIZE],
    pub auth: [u8; EncryptedMessage::AUTH_SIZE],
}
