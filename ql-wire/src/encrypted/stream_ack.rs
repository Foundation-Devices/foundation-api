use std::mem::size_of;

use zerocopy::{
    byte_slice::ByteSlice, FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned,
};

use super::StreamId;
use crate::{
    codec::{parse, push_value, read_exact, U32Le, U64Le},
    WireError,
};

/// acknowledges a contiguous prefix plus optional selective ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamAck {
    pub stream_id: StreamId,
    pub acked_prefix: u64,
    pub ranges: Vec<StreamAckRange>,
}

/// one acknowledged range after the acked prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamAckRange {
    pub start_offset: u64,
    pub end_offset: u64,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct StreamAckRangeWire {
    pub start_offset: U64Le,
    pub end_offset: U64Le,
}

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct StreamAckWire {
    pub stream_id: U32Le,
    pub acked_prefix: U64Le,
    pub ranges: [u8],
}

pub struct StreamAckRangeIter<'a> {
    remaining: &'a [u8],
}

impl StreamAck {
    pub const MIN_WIRE_SIZE: usize = size_of::<U32Le>() + size_of::<U64Le>();

    pub fn parse<B: ByteSlice>(bytes: B) -> Result<Ref<B, StreamAckWire>, WireError> {
        let wire = parse(bytes)?;
        validate_ack_frame(&wire)?;
        Ok(wire)
    }

    pub fn encoded_len(&self) -> usize {
        Self::MIN_WIRE_SIZE + self.ranges.len() * size_of::<StreamAckRangeWire>()
    }

    pub fn from_wire(wire: &StreamAckWire) -> Result<Self, WireError> {
        validate_ack_frame(wire)?;
        Ok(Self {
            stream_id: wire.stream_id(),
            acked_prefix: wire.acked_prefix(),
            ranges: wire.ranges().collect(),
        })
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.stream_id.0.to_le_bytes());
        out.extend_from_slice(&self.acked_prefix.to_le_bytes());
        for range in &self.ranges {
            push_value(
                out,
                &StreamAckRangeWire {
                    start_offset: U64Le::new(range.start_offset),
                    end_offset: U64Le::new(range.end_offset),
                },
            );
        }
    }
}

impl StreamAckWire {
    pub fn stream_id(&self) -> StreamId {
        StreamId(self.stream_id.get())
    }

    pub fn acked_prefix(&self) -> u64 {
        self.acked_prefix.get()
    }

    pub fn ranges(&self) -> StreamAckRangeIter<'_> {
        StreamAckRangeIter {
            remaining: &self.ranges,
        }
    }
}

impl Iterator for StreamAckRangeIter<'_> {
    type Item = StreamAckRange;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let (head, tail) = self.remaining.split_at(size_of::<StreamAckRangeWire>());
        self.remaining = tail;
        let wire: StreamAckRangeWire =
            read_exact(head).expect("stream ack ranges are validated before iteration");
        Some(StreamAckRange {
            start_offset: wire.start_offset.get(),
            end_offset: wire.end_offset.get(),
        })
    }
}

fn validate_ack_frame(wire: &StreamAckWire) -> Result<(), WireError> {
    if wire.ranges.len() % size_of::<StreamAckRangeWire>() != 0 {
        return Err(WireError::InvalidPayload);
    }

    let acked_prefix = wire.acked_prefix();
    let mut previous_end = acked_prefix;
    for range in wire.ranges() {
        if range.start_offset < acked_prefix
            || range.start_offset >= range.end_offset
            || range.start_offset < previous_end
        {
            return Err(WireError::InvalidPayload);
        }
        previous_end = range.end_offset;
    }

    Ok(())
}
