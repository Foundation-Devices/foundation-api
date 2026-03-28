use crate::{codec, ControlMeta, MlDsaSignature, WireError};

mod crypto;
pub use crypto::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unpair {
    pub meta: ControlMeta,
    pub signature: MlDsaSignature,
}

impl Unpair {
    pub const WIRE_SIZE: usize = ControlMeta::ENCODED_LEN + MlDsaSignature::SIZE;

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let unpair = Self {
            meta: ControlMeta::decode_from(&mut reader)?,
            signature: MlDsaSignature::from_data(reader.take_array()?),
        };
        reader.finish()?;
        Ok(unpair)
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        self.meta.encode_into(out);
        codec::push_bytes(out, self.signature.as_bytes());
    }
}
