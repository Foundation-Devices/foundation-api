use crate::{codec, ByteSlice, WireEncode, WireError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct XID(pub [u8; Self::SIZE]);

impl XID {
    pub const SIZE: usize = 16;
}

impl WireEncode for XID {
    fn encoded_len(&self) -> usize {
        Self::SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for XID {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self(reader.decode()?))
    }
}
