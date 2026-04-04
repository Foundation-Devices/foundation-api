use super::StreamId;
use crate::{codec, ByteChunks, ByteSlice, WireError};

/// carries bytes for a stream and may finish that sending direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamData<B> {
    pub stream_id: StreamId,
    pub offset: u64,
    pub fin: bool,
    pub bytes: B,
}

impl<B> StreamData<B> {
    pub const MIN_WIRE_SIZE: usize = size_of::<StreamId>() + size_of::<u64>() + size_of::<u8>();
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

impl<B: ByteChunks> StreamData<B> {
    pub fn wire_size(&self) -> usize {
        Self::MIN_WIRE_SIZE + self.bytes.len()
    }

    pub fn encode_into(&self, out: &mut [u8]) {
        assert_eq!(out.len(), self.wire_size());
        let out = codec::write_u32(out, self.stream_id.0);
        let out = codec::write_u64(out, self.offset);
        let mut out = codec::write_bool(out, self.fin);
        for chunk in self.bytes.chunks() {
            out = codec::write_bytes(out, chunk);
        }
    }
}
