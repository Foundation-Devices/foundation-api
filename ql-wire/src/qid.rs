use crate::{codec, ByteSlice, MlKemPublicKey, QlHash, WireEncode, WireError, ML_KEM_SUITE_TAG};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct QID(pub [u8; Self::SIZE]);

impl QID {
    pub const SIZE: usize = 16;

    pub fn derive(crypto: &impl QlHash, mlkem_public_key: &MlKemPublicKey) -> Self {
        let digest = crypto.sha256(&[
            b"quantum-link qid v1",
            ML_KEM_SUITE_TAG,
            mlkem_public_key.as_bytes(),
        ]);
        let mut qid = [0u8; Self::SIZE];
        qid.copy_from_slice(&digest[..Self::SIZE]);
        Self(qid)
    }

    pub fn matches_public_key(
        &self,
        crypto: &impl QlHash,
        mlkem_public_key: &MlKemPublicKey,
    ) -> bool {
        *self == Self::derive(crypto, mlkem_public_key)
    }
}

impl WireEncode for QID {
    fn encoded_len(&self) -> usize {
        Self::SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for QID {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self(reader.decode()?))
    }
}
