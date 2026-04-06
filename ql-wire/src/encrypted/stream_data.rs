use super::StreamId;
use crate::{codec, ByteChunks, ByteSlice, VarInt, WireError};

/// carries bytes for a stream and may finish that sending direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamData<B> {
    pub stream_id: StreamId,
    pub offset: VarInt,
    pub fin: bool,
    pub bytes: B,
}

impl<B> StreamData<B> {
    /// Conservative constant overhead for callers that still budget with a fixed header size.
    pub const MIN_WIRE_SIZE: usize = StreamId::MAX_ENCODED_LEN + VarInt::MAX_SIZE + size_of::<u8>();
}

impl<B: ByteSlice> StreamData<B> {
    pub fn parse(bytes: B) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        Ok(Self {
            stream_id: StreamId(reader.take_varint()?),
            offset: reader.take_varint()?,
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
    pub fn header_len(&self) -> usize {
        self.stream_id.encoded_len() + self.offset.size() + size_of::<u8>()
    }

    pub fn wire_size(&self) -> usize {
        self.header_len() + self.bytes.len()
    }

    pub fn encode_into(&self, out: &mut [u8]) {
        let out = codec::write_varint(out, self.stream_id.0);
        let out = codec::write_varint(out, self.offset);
        let mut out = codec::write_bool(out, self.fin);
        for chunk in self.bytes.chunks() {
            out = codec::write_bytes(out, chunk);
        }
    }
}
