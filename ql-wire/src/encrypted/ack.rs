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

    pub fn encode_into(&self, out: &mut [u8]) {
        assert_eq!(out.len(), self.encoded_len());
        let mut out = out;
        for range in &self.ranges {
            let (encoded, rest) = out.split_at_mut(Self::RANGE_ENCODED_LEN);
            let encoded = codec::write_u64(encoded, range.start);
            let _ = codec::write_u64(encoded, range.end);
            out = rest;
        }
    }
}
