use crate::{codec, ByteSlice, WireDecode, WireEncode, WireError, ENCRYPTED_MESSAGE_AUTH_SIZE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage<B> {
    pub auth: [u8; ENCRYPTED_MESSAGE_AUTH_SIZE],
    pub ciphertext: B,
}

impl<B> EncryptedMessage<B> {
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

impl<B: AsRef<[u8]>> WireEncode for EncryptedMessage<B> {
    fn encoded_len(&self) -> usize {
        ENCRYPTED_MESSAGE_AUTH_SIZE + self.ciphertext.as_ref().len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.auth.encode(out);
        self.ciphertext.as_ref().encode(out);
    }
}
