use bytes::Buf;
use ql_codec::{encode_bytes_raw, BufView, ByteSlice, Decode, Encode};

use crate::ENCRYPTED_MESSAGE_AUTH_SIZE;

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

impl<B: ByteSlice> Decode<B> for EncryptedMessage<B> {
    fn decode(reader: &mut ql_codec::Reader<B>) -> Result<Self, ql_codec::Error> {
        Ok(Self {
            auth: reader.decode()?,
            ciphertext: reader.take_all(),
        })
    }
}

impl<B: BufView> Encode for EncryptedMessage<B> {
    fn encoded_len(&self) -> usize {
        self.auth.encoded_len() + self.ciphertext.buf().remaining()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.auth.encode(out);
        encode_bytes_raw(&self.ciphertext, out);
    }
}
