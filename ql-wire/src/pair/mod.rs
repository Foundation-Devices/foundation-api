use crate::{
    codec, encrypted_message::EncryptedMessage, ByteSlice, ControlMeta, MlDsaPublicKey,
    MlDsaSignature, MlKemCiphertext, MlKemPublicKey, WireError, XID,
};

mod crypto;
pub use crypto::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairRequestRecord<B> {
    pub kem_ct: MlKemCiphertext,
    pub encrypted: EncryptedMessage<B>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairRequestBody {
    pub meta: ControlMeta,
    pub xid: XID,
    pub signing_pub_key: MlDsaPublicKey,
    pub encapsulation_pub_key: MlKemPublicKey,
    pub proof: MlDsaSignature,
}

impl<B: ByteSlice> PairRequestRecord<B> {
    pub fn parse(bytes: B) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        Ok(Self {
            kem_ct: MlKemCiphertext::from_data(reader.take_array()?),
            encrypted: EncryptedMessage::parse(reader.take_rest())?,
        })
    }
}

impl<B> PairRequestRecord<B> {
    pub fn into_owned(self) -> PairRequestRecord<Vec<u8>>
    where
        B: AsRef<[u8]>,
    {
        PairRequestRecord {
            kem_ct: self.kem_ct,
            encrypted: self.encrypted.into_owned(),
        }
    }
}

impl<B: AsRef<[u8]>> PairRequestRecord<B> {
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        codec::push_bytes(out, self.kem_ct.as_bytes());
        self.encrypted.encode_into(out);
    }
}

impl PairRequestBody {
    pub const ENCODED_LEN: usize = ControlMeta::ENCODED_LEN
        + XID::SIZE
        + MlDsaPublicKey::SIZE
        + MlKemPublicKey::SIZE
        + MlDsaSignature::SIZE;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        self.meta.encode_into(out);
        codec::push_bytes(out, &self.xid.0);
        codec::push_bytes(out, self.signing_pub_key.as_bytes());
        codec::push_bytes(out, self.encapsulation_pub_key.as_bytes());
        codec::push_bytes(out, self.proof.as_bytes());
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        self.encode_into(&mut out);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let body = Self {
            meta: ControlMeta::decode_from(&mut reader)?,
            xid: XID(reader.take_array()?),
            signing_pub_key: MlDsaPublicKey::from_data(reader.take_array()?),
            encapsulation_pub_key: MlKemPublicKey::from_data(reader.take_array()?),
            proof: MlDsaSignature::from_data(reader.take_array()?),
        };
        reader.finish()?;
        Ok(body)
    }
}
