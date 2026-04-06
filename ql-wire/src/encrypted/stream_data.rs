use super::StreamId;
use crate::{codec, ByteChunks, ByteSlice, VarInt, WireDecode, WireEncode, WireError};

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

impl<B: ByteSlice> WireDecode<B> for StreamData<B> {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            stream_id: reader.decode()?,
            offset: reader.decode()?,
            fin: reader.decode()?,
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
        self.stream_id.encoded_len() + self.offset.encoded_len() + size_of::<u8>()
    }
}

impl<B: ByteChunks> WireEncode for StreamData<B> {
    fn encoded_len(&self) -> usize {
        self.header_len() + self.bytes.len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.stream_id.encode(out);
        self.offset.encode(out);
        self.fin.encode(out);
        for chunk in self.bytes.chunks() {
            chunk.encode(out);
        }
    }
}
