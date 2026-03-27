use std::mem::size_of;

use zerocopy::{
    byte_slice::ByteSlice, FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned,
};

use super::StreamId;
use crate::{codec::{parse, push_value, U32Le, U64Le}, WireError};

/// advertises the highest byte offset the peer may send on a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamWindow {
    pub stream_id: StreamId,
    pub maximum_offset: u64,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct StreamWindowWire {
    pub stream_id: U32Le,
    pub maximum_offset: U64Le,
}

impl StreamWindow {
    pub const WIRE_SIZE: usize = size_of::<StreamWindowWire>();

    pub fn parse<B: ByteSlice>(bytes: B) -> Result<Ref<B, StreamWindowWire>, WireError> {
        if bytes.len() != Self::WIRE_SIZE {
            return Err(WireError::InvalidPayload);
        }
        parse(bytes)
    }

    pub fn from_wire(wire: &StreamWindowWire) -> Self {
        Self {
            stream_id: StreamId(wire.stream_id.get()),
            maximum_offset: wire.maximum_offset.get(),
        }
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        push_value(
            out,
            &StreamWindowWire {
                stream_id: U32Le::new(self.stream_id.0),
                maximum_offset: U64Le::new(self.maximum_offset),
            },
        );
    }
}
