use ql_codec::{ByteSlice, Encode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct HandshakeId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeMeta {
    pub handshake_id: HandshakeId,
}

impl<B: ByteSlice> ql_codec::Decode<B> for HandshakeId {
    fn decode(reader: &mut ql_codec::Reader<B>) -> Result<Self, ql_codec::Error> {
        Ok(Self(reader.decode()?))
    }
}

impl Encode for HandshakeId {
    fn encoded_len(&self) -> usize {
        size_of::<u32>()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.encode(out);
    }
}

impl HandshakeMeta {
    pub const WIRE_SIZE: usize = size_of::<u32>();
}

impl Encode for HandshakeMeta {
    fn encoded_len(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.handshake_id.encode(out);
    }
}

impl<B: ByteSlice> ql_codec::Decode<B> for HandshakeMeta {
    fn decode(reader: &mut ql_codec::Reader<B>) -> Result<Self, ql_codec::Error> {
        Ok(Self {
            handshake_id: reader.decode()?,
        })
    }
}
