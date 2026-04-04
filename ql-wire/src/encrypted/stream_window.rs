use super::StreamId;
use crate::{codec, ByteSlice, WireError};

/// advertises the highest byte offset the peer may send on a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamWindow {
    pub stream_id: StreamId,
    pub maximum_offset: u64,
}

impl StreamWindow {
    pub const WIRE_SIZE: usize = size_of::<StreamId>() + size_of::<u64>();

    pub fn encode_into(&self, out: &mut [u8]) {
        let out = codec::write_u32(out, self.stream_id.0);
        let _ = codec::write_u64(out, self.maximum_offset);
    }
}

impl<B: ByteSlice> codec::WireParse<B> for StreamWindow {
    fn parse(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            stream_id: StreamId(reader.take_u32()?),
            maximum_offset: reader.take_u64()?,
        })
    }
}
