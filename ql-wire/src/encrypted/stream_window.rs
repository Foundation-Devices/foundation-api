use super::StreamId;
use crate::{codec, ByteSlice, VarInt, WireEncode, WireError};

/// advertises the highest byte offset the peer may send on a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamWindow {
    pub stream_id: StreamId,
    pub maximum_offset: VarInt,
}

impl WireEncode for StreamWindow {
    fn encoded_len(&self) -> usize {
        self.stream_id.encoded_len() + self.maximum_offset.encoded_len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.stream_id.encode(out);
        self.maximum_offset.encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for StreamWindow {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            stream_id: reader.decode()?,
            maximum_offset: reader.decode()?,
        })
    }
}
