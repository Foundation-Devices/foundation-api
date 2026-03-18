use zerocopy::{
    byte_slice::ByteSlice, FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned,
};

use super::StreamId;
use crate::{
    codec::{parse, push_value, U32Le, U64Le},
    WireError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamChunk {
    pub stream_id: StreamId,
    pub offset: u64,
    pub fin: bool,
    pub bytes: Vec<u8>,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct StreamChunkWire {
    pub stream_id: U32Le,
    pub offset: U64Le,
    pub fin: u8,
    pub bytes: [u8],
}

pub type StreamChunkRef<B> = Ref<B, StreamChunkWire>;

impl StreamChunkWire {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<StreamChunkRef<B>, WireError> {
        parse(bytes)
    }

    pub fn to_stream_chunk(&self) -> Result<StreamChunk, WireError> {
        Ok(StreamChunk {
            stream_id: StreamId(self.stream_id.get()),
            offset: self.offset.get(),
            bytes: self.bytes.to_vec(),
            fin: crate::codec::read_byte(self.fin)?,
        })
    }
}

impl StreamChunk {
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        let header = StreamChunkHeaderWire {
            stream_id: U32Le::new(self.stream_id.0),
            offset: U64Le::new(self.offset),
            fin: u8::from(self.fin),
        };
        push_value(out, &header);
        out.extend_from_slice(&self.bytes);
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct StreamChunkHeaderWire {
    stream_id: U32Le,
    offset: U64Le,
    fin: u8,
}
