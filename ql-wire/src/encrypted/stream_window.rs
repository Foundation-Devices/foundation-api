use std::mem::size_of;

use super::StreamId;
use crate::{codec, WireError};

/// advertises the highest byte offset the peer may send on a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamWindow {
    pub stream_id: StreamId,
    pub maximum_offset: u64,
}

impl StreamWindow {
    pub const WIRE_SIZE: usize = size_of::<u32>() + size_of::<u64>();

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        codec::push_u32(out, self.stream_id.0);
        codec::push_u64(out, self.maximum_offset);
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let window = Self {
            stream_id: StreamId(reader.take_u32()?),
            maximum_offset: reader.take_u64()?,
        };
        reader.finish()?;
        Ok(window)
    }
}
