use std::{fmt, ops::RangeInclusive};

use ql_codec::{ByteSlice, Encode, Error};

use crate::RecordSeq;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordAck {
    largest_acked: RecordSeq,
    first_range_len: u64,
    blocks: Box<[RecordAckBlock]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordAckBlock {
    pub gap: u64,
    pub range_len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordAckRangeError {
    Empty,
    InvertedRange,
    NotCanonical,
}

impl RecordAck {
    /// Build a record ACK from canonical ranges ordered from highest to lowest sequence number.
    ///
    /// Ranges must be:
    /// - non-empty
    /// - individually valid (`start <= end`)
    /// - strictly descending
    /// - separated by at least one missing sequence number
    pub fn from_ranges<I>(ranges: I) -> Result<Self, RecordAckRangeError>
    where
        I: IntoIterator<Item = RangeInclusive<RecordSeq>>,
    {
        let mut builder = RecordAckBuilder::new();
        for range in ranges {
            let pushed = builder.try_push_range(range, usize::MAX)?;
            if !pushed {
                unreachable!("record ack should fit inside usize::MAX");
            }
        }
        builder.build()
    }

    pub fn ranges(&self) -> RecordAckRangeIter<'_> {
        RecordAckRangeIter {
            largest_acked: self.largest_acked.0,
            first_range_len: Some(self.first_range_len),
            previous_start: None,
            blocks: self.blocks.iter(),
        }
    }

    pub fn contains(&self, seq: u64) -> bool {
        let seq = RecordSeq(seq);
        self.ranges().any(|range| range.contains(&seq))
    }

    fn block_count_len(block_count: usize) -> usize {
        ql_codec::varint::encoded_len(block_count)
    }
}

impl RecordAckBlock {
    fn encoded_len(&self) -> usize {
        ql_codec::varint::encoded_len(self.gap) + ql_codec::varint::encoded_len(self.range_len)
    }
}

impl fmt::Display for RecordAckRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("record ack requires at least one acknowledged range"),
            Self::InvertedRange => {
                f.write_str("record ack range start must be less than or equal to end")
            }
            Self::NotCanonical => f.write_str(
                "record ack ranges must be passed in descending, disjoint order with a gap between adjacent ranges",
            ),
        }
    }
}

impl std::error::Error for RecordAckRangeError {}

pub struct RecordAckRangeIter<'a> {
    largest_acked: u64,
    first_range_len: Option<u64>,
    previous_start: Option<u64>,
    blocks: std::slice::Iter<'a, RecordAckBlock>,
}

impl Iterator for RecordAckRangeIter<'_> {
    type Item = RangeInclusive<RecordSeq>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(first_range_len) = self.first_range_len.take() {
            let end = self.largest_acked;
            let start = end - first_range_len;
            self.previous_start = Some(start);
            return Some(RecordSeq(start)..=RecordSeq(end));
        }

        let block = self.blocks.next()?;
        let previous_start = self
            .previous_start
            .expect("first ack range is always yielded");
        // gap is encoded as missing_count - 1, so decoding steps back by gap + 2.
        let end = previous_start - block.gap - 2;
        let start = end - block.range_len;
        self.previous_start = Some(start);
        Some(RecordSeq(start)..=RecordSeq(end))
    }
}

impl Encode for RecordAck {
    fn encoded_len(&self) -> usize {
        self.largest_acked.encoded_len()
            + Self::block_count_len(self.blocks.len())
            + ql_codec::varint::encoded_len(self.first_range_len)
            + self
                .blocks
                .iter()
                .map(RecordAckBlock::encoded_len)
                .sum::<usize>()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.largest_acked.encode(out);
        ql_codec::varint::encode(self.blocks.len(), out);
        ql_codec::varint::encode(self.first_range_len, out);
        for block in &self.blocks {
            ql_codec::varint::encode(block.gap, out);
            ql_codec::varint::encode(block.range_len, out);
        }
    }
}

impl<B: ByteSlice> ql_codec::Decode<B> for RecordAck {
    fn decode(reader: &mut ql_codec::Reader<B>) -> Result<Self, Error> {
        let largest_acked = reader.decode()?;
        let block_count = reader.decode_varint::<usize>()?;
        let first_range_len = reader.decode_varint()?;
        let mut blocks = Vec::with_capacity(block_count);
        for _ in 0..block_count {
            blocks.push(RecordAckBlock {
                gap: reader.decode_varint()?,
                range_len: reader.decode_varint()?,
            });
        }

        let ack = Self {
            largest_acked,
            first_range_len,
            blocks: blocks.into_boxed_slice(),
        };

        // validate
        {
            let mut previous_start = ack
                .largest_acked
                .0
                .checked_sub(ack.first_range_len)
                .ok_or(Error::InvalidRange)?;

            for block in &ack.blocks {
                let end = previous_start
                    .checked_sub(block.gap.checked_add(2).ok_or(Error::InvalidRange)?)
                    .ok_or(Error::InvalidRange)?;
                previous_start = end
                    .checked_sub(block.range_len)
                    .ok_or(Error::InvalidRange)?;
            }
        }
        Ok(ack)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordAckBuilder {
    largest_acked: Option<RecordSeq>,
    first_range_len: Option<u64>,
    blocks: Vec<RecordAckBlock>,
    previous_start: Option<u64>,
    wire_len: usize,
}

impl RecordAckBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn try_push_range(
        &mut self,
        range: RangeInclusive<RecordSeq>,
        max_wire_size: usize,
    ) -> Result<bool, RecordAckRangeError> {
        let start = range.start().0;
        let end = range.end().0;
        if start > end {
            return Err(RecordAckRangeError::InvertedRange);
        }

        let range_len = end - start;
        if let Some(previous_start) = self.previous_start {
            if end.saturating_add(1) >= previous_start {
                return Err(RecordAckRangeError::NotCanonical);
            }

            let gap = previous_start
                .checked_sub(end)
                .and_then(|delta| delta.checked_sub(2))
                .expect("canonical ack ranges stay separated by at least one sequence");
            let block = RecordAckBlock { gap, range_len };
            let current_block_count_len = RecordAck::block_count_len(self.blocks.len());
            let next_block_count_len = RecordAck::block_count_len(self.blocks.len() + 1);
            let next_wire_len = self.wire_len
                + (next_block_count_len - current_block_count_len)
                + block.encoded_len();
            if next_wire_len > max_wire_size {
                return Ok(false);
            }

            self.previous_start = Some(start);
            self.wire_len = next_wire_len;
            self.blocks.push(block);
            return Ok(true);
        }

        let largest_acked = RecordSeq(end);
        let wire_len = largest_acked.encoded_len()
            + RecordAck::block_count_len(0)
            + ql_codec::varint::encoded_len(range_len);
        if wire_len > max_wire_size {
            return Ok(false);
        }

        self.largest_acked = Some(largest_acked);
        self.first_range_len = Some(range_len);
        self.previous_start = Some(start);
        self.wire_len = wire_len;
        Ok(true)
    }

    pub fn build(self) -> Result<RecordAck, RecordAckRangeError> {
        let Some(largest_acked) = self.largest_acked else {
            return Err(RecordAckRangeError::Empty);
        };

        Ok(RecordAck {
            largest_acked,
            first_range_len: self.first_range_len.unwrap(),
            blocks: self.blocks.into_boxed_slice(),
        })
    }
}
#[cfg(test)]
mod tests {
    use ql_codec::{Decode, Encode, Error};

    use super::{RecordAck, RecordAckBlock, RecordAckBuilder, RecordAckRangeError};
    use crate::RecordSeq;

    #[test]
    fn encode_decode_round_trip() {
        let ack = RecordAck::from_ranges([
            RecordSeq(95)..=RecordSeq(100),
            RecordSeq(90)..=RecordSeq(92),
            RecordSeq(80)..=RecordSeq(80),
        ])
        .unwrap();
        let encoded = ack.encode_vec();

        assert_eq!(RecordAck::decode_bytes(encoded.as_slice()).unwrap(), ack);
    }

    #[test]
    fn wire_fields_match_gap_encoding() {
        let ack = RecordAck::from_ranges([
            RecordSeq(95)..=RecordSeq(100),
            RecordSeq(90)..=RecordSeq(92),
            RecordSeq(80)..=RecordSeq(80),
        ])
        .unwrap();

        assert_eq!(ack.largest_acked, RecordSeq(100));
        assert_eq!(ack.first_range_len, 5);
        assert_eq!(
            ack.blocks.as_ref(),
            &[
                RecordAckBlock {
                    gap: 1,
                    range_len: 2,
                },
                RecordAckBlock {
                    gap: 8,
                    range_len: 0,
                }
            ]
        );
    }

    #[test]
    fn builder_stops_when_budget_is_exhausted() {
        let first_only = RecordAck::from_ranges([RecordSeq(95)..=RecordSeq(100)]).unwrap();
        let mut builder = RecordAckBuilder::new();

        assert!(builder
            .try_push_range(RecordSeq(95)..=RecordSeq(100), first_only.encoded_len())
            .unwrap());
        assert!(!builder
            .try_push_range(RecordSeq(90)..=RecordSeq(92), first_only.encoded_len())
            .unwrap());
        assert_eq!(builder.build().unwrap(), first_only);
    }

    #[test]
    fn builder_rejects_non_canonical_ranges() {
        let mut builder = RecordAckBuilder::new();
        assert!(builder
            .try_push_range(RecordSeq(95)..=RecordSeq(100), usize::MAX)
            .unwrap());
        assert_eq!(
            builder.try_push_range(RecordSeq(90)..=RecordSeq(95), usize::MAX),
            Err(RecordAckRangeError::NotCanonical)
        );
    }

    #[test]
    fn rejects_unsorted_ranges() {
        assert_eq!(
            RecordAck::from_ranges([
                RecordSeq(90)..=RecordSeq(92),
                RecordSeq(95)..=RecordSeq(100)
            ]),
            Err(RecordAckRangeError::NotCanonical)
        );
    }

    #[test]
    fn rejects_touching_ranges() {
        assert_eq!(
            RecordAck::from_ranges([RecordSeq(10)..=RecordSeq(12), RecordSeq(7)..=RecordSeq(9)]),
            Err(RecordAckRangeError::NotCanonical)
        );
    }

    #[test]
    fn rejects_overlapping_ranges() {
        assert_eq!(
            RecordAck::from_ranges([RecordSeq(10)..=RecordSeq(12), RecordSeq(8)..=RecordSeq(11)]),
            Err(RecordAckRangeError::NotCanonical)
        );
    }

    #[test]
    fn contains_matches_range_membership() {
        let ack = RecordAck::from_ranges([
            RecordSeq(150)..=RecordSeq(163),
            RecordSeq(105)..=RecordSeq(110),
            RecordSeq(100)..=RecordSeq(100),
        ])
        .unwrap();

        assert!(ack.contains(100));
        assert!(ack.contains(107));
        assert!(ack.contains(163));
        assert!(!ack.contains(99));
        assert!(!ack.contains(104));
        assert!(!ack.contains(164));
    }

    #[test]
    fn empty_ack_is_rejected() {
        assert_eq!(RecordAck::from_ranges([]), Err(RecordAckRangeError::Empty));
    }

    #[test]
    fn inverted_range_is_rejected() {
        assert_eq!(
            RecordAck::from_ranges([RecordSeq(5)..=RecordSeq(4)]),
            Err(RecordAckRangeError::InvertedRange)
        );
    }

    #[test]
    fn decode_rejects_underflowing_ack_blocks() {
        let encoded = vec![
            42, // largest_acked
            1,  // block_count
            0,  // first_range_len
            41, // gap: implies a missing run larger than largest_acked
            0,  // range_len
        ];

        assert_eq!(
            RecordAck::decode_bytes(encoded.as_slice()),
            Err(Error::InvalidRange)
        );
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        assert_eq!(RecordAck::decode_bytes(&[][..]), Err(Error::UnexpectedEof));

        let encoded = RecordAck::from_ranges([RecordSeq(42)..=RecordSeq(42)])
            .unwrap()
            .encode_vec();
        assert_eq!(
            RecordAck::decode_bytes(&encoded[..encoded.len() - 1]),
            Err(Error::UnexpectedEof)
        );
    }
}
