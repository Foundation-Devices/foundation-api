use super::StreamId;
use crate::{codec, ByteSlice, VarInt, WireError};

/// advertises the highest byte offset the peer may send on a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamWindow {
    pub stream_id: StreamId,
    pub maximum_offset: VarInt,
}

impl StreamWindow {
    pub fn wire_size(&self) -> usize {
        self.stream_id.encoded_len() + self.maximum_offset.size()
    }

    pub fn encode_into(&self, out: &mut [u8]) {
        let out = codec::write_varint(out, self.stream_id.0);
        let _ = codec::write_varint(out, self.maximum_offset);
    }
}

impl<B: ByteSlice> codec::WireParse<B> for StreamWindow {
    fn parse(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            stream_id: reader.parse()?,
            maximum_offset: reader.parse()?,
        })
    }
}
