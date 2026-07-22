use ql_codec::{ByteSlice, Encode, Error, Varint};

use super::StreamId;

/// advertises the highest byte offset the peer may send on a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamWindow {
    pub stream_id: StreamId,
    pub maximum_offset: Varint<u64>,
}

impl Encode for StreamWindow {
    fn encoded_len(&self) -> usize {
        self.stream_id.encoded_len() + self.maximum_offset.encoded_len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.stream_id.encode(out);
        self.maximum_offset.encode(out);
    }
}

impl<B: ByteSlice> ql_codec::Decode<B> for StreamWindow {
    fn decode(reader: &mut ql_codec::Reader<B>) -> Result<Self, Error> {
        Ok(Self {
            stream_id: reader.decode()?,
            maximum_offset: reader.decode()?,
        })
    }
}
