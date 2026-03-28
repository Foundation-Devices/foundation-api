use crate::{
    codec, encrypted_message::EncryptedMessage, ByteSlice, ControlMeta, MlDsaSignature,
    MlKemCiphertext, Nonce, WireError,
};

mod crypto;
pub use crypto::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub meta: ControlMeta,
    pub nonce: Nonce,
    pub kem_ct: MlKemCiphertext,
    pub signature: MlDsaSignature,
}

impl Hello {
    pub const ENCODED_LEN: usize =
        ControlMeta::ENCODED_LEN + Nonce::SIZE + MlKemCiphertext::SIZE + MlDsaSignature::SIZE;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        self.meta.encode_into(out);
        codec::push_bytes(out, &self.nonce.0);
        codec::push_bytes(out, self.kem_ct.as_bytes());
        codec::push_bytes(out, self.signature.as_bytes());
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let hello = Self {
            meta: ControlMeta::decode_from(&mut reader)?,
            nonce: Nonce(reader.take_array()?),
            kem_ct: MlKemCiphertext::from_data(reader.take_array()?),
            signature: MlDsaSignature::from_data(reader.take_array()?),
        };
        reader.finish()?;
        Ok(hello)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloReply {
    pub meta: ControlMeta,
    pub nonce: Nonce,
    pub kem_ct: MlKemCiphertext,
    pub signature: MlDsaSignature,
}

impl HelloReply {
    pub const ENCODED_LEN: usize =
        ControlMeta::ENCODED_LEN + Nonce::SIZE + MlKemCiphertext::SIZE + MlDsaSignature::SIZE;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        self.meta.encode_into(out);
        codec::push_bytes(out, &self.nonce.0);
        codec::push_bytes(out, self.kem_ct.as_bytes());
        codec::push_bytes(out, self.signature.as_bytes());
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let reply = Self {
            meta: ControlMeta::decode_from(&mut reader)?,
            nonce: Nonce(reader.take_array()?),
            kem_ct: MlKemCiphertext::from_data(reader.take_array()?),
            signature: MlDsaSignature::from_data(reader.take_array()?),
        };
        reader.finish()?;
        Ok(reply)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirm {
    pub meta: ControlMeta,
    pub signature: MlDsaSignature,
}

impl Confirm {
    pub const ENCODED_LEN: usize = ControlMeta::ENCODED_LEN + MlDsaSignature::SIZE;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        self.meta.encode_into(out);
        codec::push_bytes(out, self.signature.as_bytes());
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let confirm = Self {
            meta: ControlMeta::decode_from(&mut reader)?,
            signature: MlDsaSignature::from_data(reader.take_array()?),
        };
        reader.finish()?;
        Ok(confirm)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready<B> {
    pub encrypted: EncryptedMessage<B>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyBody {
    pub meta: ControlMeta,
}

impl<B: ByteSlice> Ready<B> {
    pub fn parse(bytes: B) -> Result<Self, WireError> {
        Ok(Self {
            encrypted: EncryptedMessage::parse(bytes)?,
        })
    }
}

impl<B> Ready<B> {
    pub fn into_owned(self) -> Ready<Vec<u8>>
    where
        B: ByteSlice,
    {
        Ready {
            encrypted: self.encrypted.into_owned(),
        }
    }
}

impl<B: AsRef<[u8]>> Ready<B> {
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        self.encrypted.encode_into(out);
    }
}

impl Ready<Vec<u8>> {
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        EncryptedMessage::parse(bytes).map(|encrypted| Self {
            encrypted: encrypted.into_owned(),
        })
    }
}

impl ReadyBody {
    pub fn encode(&self) -> Vec<u8> {
        self.meta.encode()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(Self {
            meta: ControlMeta::decode(bytes)?,
        })
    }
}
