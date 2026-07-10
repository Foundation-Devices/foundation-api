use ql_codec::{ByteSlice, Encode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct HandshakeId(pub u32);

impl HandshakeId {
    pub const WIRE_SIZE: usize = size_of::<u32>();
}

impl<B: ByteSlice> ql_codec::Decode<B> for HandshakeId {
    fn decode(reader: &mut ql_codec::Reader<B>) -> Result<Self, ql_codec::Error> {
        Ok(Self(reader.decode()?))
    }
}

impl Encode for HandshakeId {
    fn encoded_len(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.encode(out);
    }
}
