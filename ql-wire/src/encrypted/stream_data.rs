use std::mem::size_of;

use super::StreamId;
use crate::{codec, ByteSlice, WireError};

/// carries bytes for a stream and may finish that sending direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamData<B> {
    pub stream_id: StreamId,
    pub offset: u64,
    pub fin: bool,
    pub bytes: B,
}

impl<B> StreamData<B> {
    pub const MIN_WIRE_SIZE: usize = size_of::<u32>() + size_of::<u64>() + size_of::<u8>();
}

impl<B: ByteSlice> StreamData<B> {
    pub fn parse(bytes: B) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        Ok(Self {
            stream_id: StreamId(reader.take_u32()?),
            offset: reader.take_u64()?,
            fin: reader.take_bool()?,
            bytes: reader.take_rest(),
        })
    }
}

impl<B> StreamData<B> {
    pub fn into_owned(self) -> StreamData<Vec<u8>>
    where
        B: ByteSlice,
    {
        StreamData {
            stream_id: self.stream_id,
            offset: self.offset,
            fin: self.fin,
            bytes: self.bytes.to_vec(),
        }
    }
}

impl<B: AsRef<[u8]>> StreamData<B> {
    pub fn encoded_len(&self) -> usize {
        Self::MIN_WIRE_SIZE + self.bytes.as_ref().len()
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        codec::push_u32(out, self.stream_id.0);
        codec::push_u64(out, self.offset);
        codec::push_u8(out, u8::from(self.fin));
        codec::push_bytes(out, self.bytes.as_ref());
    }
}
