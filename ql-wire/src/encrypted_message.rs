use crate::{
    codec, ByteSlice, Nonce, QlCrypto, SessionKey, WireEncode, WireError, WireDecode,
    ENCRYPTED_MESSAGE_AUTH_SIZE,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage<B> {
    pub auth: [u8; ENCRYPTED_MESSAGE_AUTH_SIZE],
    pub ciphertext: B,
}

impl<B> EncryptedMessage<B> {
    pub const AUTH_SIZE: usize = ENCRYPTED_MESSAGE_AUTH_SIZE;
    pub const HEADER_LEN: usize = Self::AUTH_SIZE;

    pub fn into_owned(self) -> EncryptedMessage<Vec<u8>>
    where
        B: ByteSlice,
    {
        EncryptedMessage {
            auth: self.auth,
            ciphertext: self.ciphertext.to_vec(),
        }
    }
}

impl<B: ByteSlice> WireDecode<B> for EncryptedMessage<B> {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            auth: reader.decode()?,
            ciphertext: reader.take_rest(),
        })
    }
}

impl<B: AsRef<[u8]>> EncryptedMessage<B> {
    pub fn decrypt(
        &self,
        crypto: &impl QlCrypto,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
    ) -> Result<Vec<u8>, WireError> {
        let mut plaintext = self.ciphertext.as_ref().to_vec();
        if !crypto.aes256_gcm_decrypt(key, nonce, aad, &mut plaintext, &self.auth) {
            return Err(WireError::DecryptFailed);
        }
        Ok(plaintext)
    }
}

impl<B: AsRef<[u8]>> WireEncode for EncryptedMessage<B> {
    fn encoded_len(&self) -> usize {
        Self::HEADER_LEN + self.ciphertext.as_ref().len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.auth.encode(out);
        self.ciphertext.as_ref().encode(out);
    }
}

impl<B: AsMut<[u8]>> EncryptedMessage<B> {
    pub fn decrypt_in_place(
        mut self,
        crypto: &impl QlCrypto,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
    ) -> Result<B, WireError> {
        let ciphertext = self.ciphertext.as_mut();
        if !crypto.aes256_gcm_decrypt(key, nonce, aad, ciphertext, &self.auth) {
            return Err(WireError::DecryptFailed);
        }
        Ok(self.ciphertext)
    }
}

impl EncryptedMessage<Vec<u8>> {
    pub fn encrypt(
        crypto: &impl QlCrypto,
        key: &SessionKey,
        mut plaintext: Vec<u8>,
        nonce: &Nonce,
        aad: &[u8],
    ) -> Self {
        let auth = crypto.aes256_gcm_encrypt(key, nonce, aad, &mut plaintext);
        Self {
            auth,
            ciphertext: plaintext,
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(EncryptedMessage::decode_exact(bytes)?.into_owned())
    }
}
