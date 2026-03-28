use crate::{
    codec, ByteSlice, Nonce, QlCrypto, SessionKey, WireError, ENCRYPTED_MESSAGE_AUTH_SIZE,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage<B> {
    pub nonce: Nonce,
    pub auth: [u8; ENCRYPTED_MESSAGE_AUTH_SIZE],
    pub ciphertext: B,
}

impl<B> EncryptedMessage<B> {
    pub const AUTH_SIZE: usize = ENCRYPTED_MESSAGE_AUTH_SIZE;
    pub const HEADER_LEN: usize = Nonce::SIZE + Self::AUTH_SIZE;

    pub fn into_owned(self) -> EncryptedMessage<Vec<u8>>
    where
        B: AsRef<[u8]>,
    {
        EncryptedMessage {
            nonce: self.nonce,
            auth: self.auth,
            ciphertext: self.ciphertext.as_ref().to_vec(),
        }
    }
}

impl<B: ByteSlice> EncryptedMessage<B> {
    pub fn parse(bytes: B) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        Ok(Self {
            nonce: Nonce(reader.take_array()?),
            auth: reader.take_array()?,
            ciphertext: reader.take_rest(),
        })
    }
}

impl<B: AsRef<[u8]>> EncryptedMessage<B> {
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        codec::push_bytes(out, &self.nonce.0);
        codec::push_bytes(out, &self.auth);
        codec::push_bytes(out, self.ciphertext.as_ref());
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::HEADER_LEN + self.ciphertext.as_ref().len());
        self.encode_into(&mut out);
        out
    }

    pub fn decrypt(
        &self,
        crypto: &impl QlCrypto,
        key: &SessionKey,
        aad: &[u8],
    ) -> Result<Vec<u8>, WireError> {
        let mut plaintext = self.ciphertext.as_ref().to_vec();
        if !crypto.decrypt_with_aead(key, &self.nonce, aad, &mut plaintext, &self.auth) {
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
        aad: &[u8],
    ) -> Result<B, WireError> {
        let ciphertext = self.ciphertext.as_mut();
        if !crypto.decrypt_with_aead(key, &self.nonce, aad, ciphertext, &self.auth) {
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

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(EncryptedMessage::parse(bytes)?.into_owned())
    }
}
