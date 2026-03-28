use std::mem::size_of;

use crate::{codec, WireError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordAck {
    pub ranges: Vec<RecordAckRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordAckRange {
    pub start: u64,
    pub end: u64,
}

impl RecordAck {
    pub const FRAME_OVERHEAD: usize = std::mem::size_of::<u8>() + size_of::<u16>();
    pub const RANGE_ENCODED_LEN: usize = size_of::<u64>() + size_of::<u64>();

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.is_empty() || bytes.len() % Self::RANGE_ENCODED_LEN != 0 {
            return Err(WireError::InvalidPayload);
        }

        let mut reader = codec::Reader::new(bytes);
        let mut ranges = Vec::with_capacity(bytes.len() / Self::RANGE_ENCODED_LEN);
        let mut previous_end = 0;

        while !reader.is_empty() {
            let range = RecordAckRange {
                start: reader.take_u64()?,
                end: reader.take_u64()?,
            };

            if range.start >= range.end {
                return Err(WireError::InvalidPayload);
            }
            if !ranges.is_empty() && range.start < previous_end {
                return Err(WireError::InvalidPayload);
            }

            previous_end = range.end;
            ranges.push(range);
        }

        Ok(Self { ranges })
    }

    pub fn encoded_len(&self) -> usize {
        self.ranges.len() * Self::RANGE_ENCODED_LEN
    }

    pub fn frame_encoded_len(&self) -> usize {
        Self::FRAME_OVERHEAD + self.encoded_len()
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        for range in &self.ranges {
            codec::push_u64(out, range.start);
            codec::push_u64(out, range.end);
        }
    }
}
