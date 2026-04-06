use crate::{codec, ByteSlice, WireError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct XID(pub [u8; Self::SIZE]);

impl XID {
    pub const SIZE: usize = 16;
}

impl<B: ByteSlice> codec::WireParse<B> for XID {
    fn parse(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self(reader.parse()?))
    }
}
