use crate::{ByteSlice, Reader, VarInt, WireDecode, WireEncode, WireError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RouteId(pub VarInt);

impl RouteId {
    pub const MAX_ENCODED_LEN: usize = VarInt::MAX_SIZE;

    pub const fn into_inner(self) -> u64 {
        self.0.into_inner()
    }
}

impl WireEncode for RouteId {
    fn encoded_len(&self) -> usize {
        self.0.size()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.encode(out);
    }
}

impl<B: ByteSlice> WireDecode<B> for RouteId {
    fn decode(reader: &mut Reader<B>) -> Result<Self, WireError> {
        Ok(Self(reader.decode()?))
    }
}
