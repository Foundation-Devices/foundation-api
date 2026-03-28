use std::mem::size_of;

use zerocopy::{
    byte_slice::ByteSlice, FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned,
};

use crate::{
    codec::{parse, push_value, read_exact, U64Le},
    WireError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordAck {
    pub ranges: Vec<RecordAckRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordAckRange {
    pub start: u64,
    pub end: u64,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct RecordAckRangeWire {
    pub start: U64Le,
    pub end: U64Le,
}

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct RecordAckQire {
    pub ranges: [u8],
}

pub struct RecordAckRangeIter<'a> {
    remaining: &'a [u8],
}

impl RecordAck {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<Ref<B, RecordAckQire>, WireError> {
        let wire = parse(bytes)?;
        validate_ack_frame(&wire)?;
        Ok(wire)
    }

    pub fn encoded_len(&self) -> usize {
        self.ranges.len() * size_of::<RecordAckRangeWire>()
    }

    pub fn from_wire(wire: &RecordAckQire) -> Result<Self, WireError> {
        validate_ack_frame(wire)?;
        Ok(Self {
            ranges: wire.ranges().collect(),
        })
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        for range in &self.ranges {
            push_value(
                out,
                &RecordAckRangeWire {
                    start: U64Le::new(range.start),
                    end: U64Le::new(range.end),
                },
            );
        }
    }
}

impl RecordAckQire {
    pub fn ranges(&self) -> RecordAckRangeIter<'_> {
        RecordAckRangeIter {
            remaining: &self.ranges,
        }
    }
}

impl Iterator for RecordAckRangeIter<'_> {
    type Item = RecordAckRange;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }

        let (head, tail) = self.remaining.split_at(size_of::<RecordAckRangeWire>());
        self.remaining = tail;
        let wire: RecordAckRangeWire =
            read_exact(head).expect("ack ranges are validated before iteration");
        Some(RecordAckRange {
            start: wire.start.get(),
            end: wire.end.get(),
        })
    }
}

fn validate_ack_frame(wire: &RecordAckQire) -> Result<(), WireError> {
    if wire.ranges.is_empty() || wire.ranges.len() % size_of::<RecordAckRangeWire>() != 0 {
        return Err(WireError::InvalidPayload);
    }

    let mut previous_end = 0;
    let mut first = true;
    for range in wire.ranges() {
        if range.start >= range.end {
            return Err(WireError::InvalidPayload);
        }
        if !first && range.start < previous_end {
            return Err(WireError::InvalidPayload);
        }
        first = false;
        previous_end = range.end;
    }

    Ok(())
}
