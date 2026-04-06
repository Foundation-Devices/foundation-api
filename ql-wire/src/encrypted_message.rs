use crate::{
    codec, ByteSlice, Nonce, QlCrypto, SessionKey, WireError, ENCRYPTED_MESSAGE_AUTH_SIZE,
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

impl<B: ByteSlice> EncryptedMessage<B> {
    pub fn parse(bytes: B) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        Ok(Self {
            auth: reader.parse()?,
            ciphertext: reader.take_rest(),
        })
    }
}

impl<B: AsRef<[u8]>> EncryptedMessage<B> {
    pub fn encode_into<'a>(&self, out: &'a mut [u8]) -> &'a mut [u8] {
        let out = codec::write_bytes(out, &self.auth);
        codec::write_bytes(out, self.ciphertext.as_ref())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0; Self::HEADER_LEN + self.ciphertext.as_ref().len()];
        let _ = self.encode_into(&mut out);
        out
    }

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
        Ok(EncryptedMessage::parse(bytes)?.into_owned())
    }
}
