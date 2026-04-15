use crate::{ByteSlice, Reader, VarInt, VarIntBoundsExceeded, WireDecode, WireEncode, WireError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RouteId(pub VarInt);

impl RouteId {
    pub const MAX_ENCODED_LEN: usize = VarInt::MAX_SIZE;

    pub const fn from_u32(value: u32) -> Self {
        Self(VarInt::from_u32(value))
    }

    pub fn from_u64(value: u64) -> Result<Self, VarIntBoundsExceeded> {
        Ok(Self(VarInt::from_u64(value)?))
    }

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

impl From<VarInt> for RouteId {
    fn from(value: VarInt) -> Self {
        Self(value)
    }
}

impl From<u32> for RouteId {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl std::fmt::Display for RouteId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
