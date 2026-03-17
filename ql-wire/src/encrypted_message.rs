use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    codec::{push_value, read_prefix, read_prefix_mut},
    Nonce, QlCrypto, SessionKey, WireError, AUTH_SIZE, NONCE_SIZE,
};

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct EncryptedMessageHeaderWire {
    nonce: [u8; NONCE_SIZE],
    auth: [u8; AUTH_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage {
    pub nonce: Nonce,
    pub auth: [u8; AUTH_SIZE],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessageRef<'a> {
    pub nonce: Nonce,
    pub auth: [u8; AUTH_SIZE],
    pub ciphertext: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedMessageMut<'a> {
    pub nonce: Nonce,
    pub auth: [u8; AUTH_SIZE],
    pub ciphertext: &'a mut [u8],
}

impl EncryptedMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NONCE_SIZE + AUTH_SIZE + self.ciphertext.len());
        self.encode_into(&mut out);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(Self::parse(bytes)?.to_owned())
    }

    pub fn parse(bytes: &[u8]) -> Result<EncryptedMessageRef<'_>, WireError> {
        EncryptedMessageRef::parse(bytes)
    }

    pub fn parse_mut(bytes: &mut [u8]) -> Result<EncryptedMessageMut<'_>, WireError> {
        EncryptedMessageMut::parse(bytes)
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let header = EncryptedMessageHeaderWire {
            nonce: self.nonce,
            auth: self.auth,
        };
        push_value(out, &header);
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

impl<'a> EncryptedMessageRef<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, WireError> {
        let (header, ciphertext) = read_prefix::<EncryptedMessageHeaderWire>(bytes)?;
        Ok(Self {
            nonce: header.nonce,
            auth: header.auth,
            ciphertext,
        })
    }

    pub fn to_owned(&self) -> EncryptedMessage {
        EncryptedMessage {
            nonce: self.nonce,
            auth: self.auth,
            ciphertext: self.ciphertext.to_vec(),
        }
    }
}

impl<'a> EncryptedMessageMut<'a> {
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, WireError> {
        let (header, ciphertext) = read_prefix_mut::<EncryptedMessageHeaderWire>(bytes)?;
        Ok(Self {
            nonce: header.nonce,
            auth: header.auth,
            ciphertext,
        })
    }

    pub fn decrypt(
        &mut self,
        crypto: &impl QlCrypto,
        key: &SessionKey,
        aad: &[u8],
    ) -> Result<&[u8], WireError> {
        if !crypto.decrypt_with_aead(key, &self.nonce, aad, self.ciphertext, &self.auth) {
            return Err(WireError::DecryptFailed);
        }
        Ok(self.ciphertext)
    }

    pub fn to_owned(&self) -> EncryptedMessage {
        EncryptedMessage {
            nonce: self.nonce,
            auth: self.auth,
            ciphertext: self.ciphertext.to_vec(),
        }
    }
}
