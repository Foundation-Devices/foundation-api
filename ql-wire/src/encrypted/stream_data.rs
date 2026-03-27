use std::mem::size_of;

use zerocopy::{
    byte_slice::ByteSlice, FromBytes, Immutable, KnownLayout, Ref, Unaligned,
};

use super::StreamId;
use crate::{codec::{parse, U32Le, U64Le}, WireError};

/// carries bytes for a stream and may finish that sending direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamData {
    pub stream_id: StreamId,
    pub offset: u64,
    pub fin: bool,
    pub bytes: Vec<u8>,
}

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct StreamDataWire {
    pub stream_id: U32Le,
    pub offset: U64Le,
    pub fin: u8,
    pub bytes: [u8],
}

impl StreamData {
    pub const MIN_WIRE_SIZE: usize =
        size_of::<U32Le>() + size_of::<U64Le>() + size_of::<u8>();

    pub fn parse<B: ByteSlice>(bytes: B) -> Result<Ref<B, StreamDataWire>, WireError> {
        if bytes.len() < Self::MIN_WIRE_SIZE {
            return Err(WireError::InvalidPayload);
        }
        let wire: Ref<B, StreamDataWire> = parse(bytes)?;
        let _ = wire.fin()?;
        Ok(wire)
    }

    pub fn encoded_len(&self) -> usize {
        Self::MIN_WIRE_SIZE + self.bytes.len()
    }

    pub fn from_wire(wire: &StreamDataWire) -> Result<Self, WireError> {
        Ok(Self {
            stream_id: wire.stream_id(),
            offset: wire.offset(),
            fin: wire.fin()?,
            bytes: wire.bytes().to_vec(),
        })
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.stream_id.0.to_le_bytes());
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.push(u8::from(self.fin));
        out.extend_from_slice(&self.bytes);
    }
}

impl StreamDataWire {
    pub fn stream_id(&self) -> StreamId {
        StreamId(self.stream_id.get())
    }

    pub fn offset(&self) -> u64 {
        self.offset.get()
    }

    pub fn fin(&self) -> Result<bool, WireError> {
        match self.fin {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::InvalidPayload),
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
