use zerocopy::{
    byte_slice::{ByteSlice, ByteSliceMut},
    FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned,
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
struct StreamChunkWire {
    pub stream_id: U32Le,
    pub offset: U64Le,
    pub fin: u8,
    pub bytes: [u8],
}

pub struct StreamChunkRef<B> {
    wire: Ref<B, StreamChunkWire>,
}

impl<B: ByteSlice> StreamChunkRef<B> {
    pub fn parse(bytes: B) -> Result<Self, WireError> {
        Ok(Self {
            wire: parse(bytes)?,
        })
    }

    pub fn stream_id(&self) -> StreamId {
        StreamId(self.wire.stream_id.get())
    }

    pub fn fin(&self) -> Result<bool, WireError> {
        match self.wire.fin {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::InvalidPayload),
        }
    }

    pub fn offset(&self) -> u64 {
        self.wire.offset.get()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.wire.bytes
    }

    pub fn to_stream_chunk(&self) -> Result<StreamChunk, WireError> {
        Ok(StreamChunk {
            stream_id: self.stream_id(),
            offset: self.offset(),
            bytes: self.bytes().to_vec(),
            fin: self.fin()?,
        })
    }
}

impl<B: ByteSliceMut> StreamChunkRef<B> {
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.wire.bytes
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
