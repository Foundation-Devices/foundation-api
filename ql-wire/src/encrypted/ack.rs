use std::{fmt, ops::RangeInclusive};

use crate::{codec, ByteSlice, RecordSeq, VarInt, WireEncode, WireError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordAck {
    largest_acked: RecordSeq,
    first_range_len: VarInt,
    blocks: Box<[RecordAckBlock]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordAckBlock {
    pub gap: VarInt,
    pub range_len: VarInt,
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
            largest_acked: self.largest_acked.into_inner(),
            first_range_len: Some(self.first_range_len),
            previous_start: None,
            blocks: self.blocks.iter(),
        }
    }

    pub fn contains(&self, seq: u64) -> bool {
        let Ok(seq) = RecordSeq::from_u64(seq) else {
            return false;
        };
        self.ranges().any(|range| range.contains(&seq))
    }

    fn block_count_len(block_count: usize) -> usize {
        VarInt::try_from(block_count).unwrap().encoded_len()
    }
}

impl RecordAckBlock {
    fn encoded_len(&self) -> usize {
        self.gap.encoded_len() + self.range_len.encoded_len()
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
    first_range_len: Option<VarInt>,
    previous_start: Option<u64>,
    blocks: std::slice::Iter<'a, RecordAckBlock>,
}

impl Iterator for RecordAckRangeIter<'_> {
    type Item = RangeInclusive<RecordSeq>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(first_range_len) = self.first_range_len.take() {
            let end = self.largest_acked;
            let start = end - first_range_len.into_inner();
            self.previous_start = Some(start);
            return Some(RecordSeq::from_u64(start).unwrap()..=RecordSeq::from_u64(end).unwrap());
        }

        let block = self.blocks.next()?;
        let previous_start = self
            .previous_start
            .expect("first ack range is always yielded");
        // gap is encoded as missing_count - 1, so decoding steps back by gap + 2.
        let end = previous_start - block.gap.into_inner() - 2;
        let start = end - block.range_len.into_inner();
        self.previous_start = Some(start);
        Some(RecordSeq::from_u64(start).unwrap()..=RecordSeq::from_u64(end).unwrap())
    }
}

impl WireEncode for RecordAck {
    fn encoded_len(&self) -> usize {
        self.largest_acked.encoded_len()
            + Self::block_count_len(self.blocks.len())
            + self.first_range_len.encoded_len()
            + self
                .blocks
                .iter()
                .map(RecordAckBlock::encoded_len)
                .sum::<usize>()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.largest_acked.encode(out);
        VarInt::try_from(self.blocks.len()).unwrap().encode(out);
        self.first_range_len.encode(out);
        for block in &self.blocks {
            block.gap.encode(out);
            block.range_len.encode(out);
        }
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for RecordAck {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        let largest_acked = reader.decode()?;
        let block_count = usize::try_from(reader.decode::<VarInt>()?.into_inner())
            .map_err(|_| WireError::InvalidPayload)?;
        let first_range_len = reader.decode::<VarInt>()?;
        let mut blocks = Vec::with_capacity(block_count);
        for _ in 0..block_count {
            blocks.push(RecordAckBlock {
                gap: reader.decode::<VarInt>()?,
                range_len: reader.decode::<VarInt>()?,
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
                .into_inner()
                .checked_sub(ack.first_range_len.into_inner())
                .ok_or(WireError::InvalidPayload)?;

            for block in &ack.blocks {
                let end = previous_start
                    .checked_sub(
                        block
                            .gap
                            .into_inner()
                            .checked_add(2)
                            .ok_or(WireError::InvalidPayload)?,
                    )
                    .ok_or(WireError::InvalidPayload)?;
                previous_start = end
                    .checked_sub(block.range_len.into_inner())
                    .ok_or(WireError::InvalidPayload)?;
            }
        }
        Ok(ack)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordAckBuilder {
    largest_acked: Option<RecordSeq>,
    first_range_len: Option<VarInt>,
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
        let start = range.start().into_inner();
        let end = range.end().into_inner();
        if start > end {
            return Err(RecordAckRangeError::InvertedRange);
        }

        let range_len = VarInt::from_u64(end - start).unwrap();
        if let Some(previous_start) = self.previous_start {
            if end.saturating_add(1) >= previous_start {
                return Err(RecordAckRangeError::NotCanonical);
            }

            let gap = previous_start
                .checked_sub(end)
                .and_then(|delta| delta.checked_sub(2))
                .expect("canonical ack ranges stay separated by at least one sequence");
            let block = RecordAckBlock {
                gap: VarInt::from_u64(gap).unwrap(),
                range_len,
            };
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

        let largest_acked = RecordSeq::from_u64(end).unwrap();
        let wire_len =
            largest_acked.encoded_len() + RecordAck::block_count_len(0) + range_len.encoded_len();
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
    use std::ops::RangeInclusive;

    use super::{RecordAck, RecordAckBlock, RecordAckBuilder, RecordAckRangeError};
    use crate::{RecordSeq, VarInt, WireDecode, WireEncode, WireError};

    fn seq(value: u64) -> RecordSeq {
        RecordSeq::from_u64(value).unwrap()
    }

    fn ack_range(start: u64, end: u64) -> RangeInclusive<RecordSeq> {
        seq(start)..=seq(end)
    }

    fn varint(value: u64) -> VarInt {
        VarInt::from_u64(value).unwrap()
    }

    #[test]
    fn encode_decode_round_trip() {
        let ack =
            RecordAck::from_ranges([ack_range(95, 100), ack_range(90, 92), ack_range(80, 80)])
                .unwrap();
        let encoded = ack.encode_vec();

        assert_eq!(RecordAck::decode_exact(encoded.as_slice()).unwrap(), ack);
    }

    #[test]
    fn wire_fields_match_gap_encoding() {
        let ack =
            RecordAck::from_ranges([ack_range(95, 100), ack_range(90, 92), ack_range(80, 80)])
                .unwrap();

        assert_eq!(ack.largest_acked, seq(100));
        assert_eq!(ack.first_range_len, varint(5));
        assert_eq!(
            ack.blocks.as_ref(),
            &[
                RecordAckBlock {
                    gap: varint(1),
                    range_len: varint(2),
                },
                RecordAckBlock {
                    gap: varint(8),
                    range_len: varint(0),
                }
            ]
        );
    }

    #[test]
    fn builder_matches_from_ranges() {
        let mut builder = RecordAckBuilder::new();
        assert!(builder
            .try_push_range(ack_range(95, 100), usize::MAX)
            .unwrap());
        assert!(builder
            .try_push_range(ack_range(90, 92), usize::MAX)
            .unwrap());
        assert!(builder
            .try_push_range(ack_range(80, 80), usize::MAX)
            .unwrap());

        assert_eq!(
            builder.build().unwrap(),
            RecordAck::from_ranges([ack_range(95, 100), ack_range(90, 92), ack_range(80, 80)])
                .unwrap()
        );
    }

    #[test]
    fn builder_stops_when_budget_is_exhausted() {
        let first_only = RecordAck::from_ranges([ack_range(95, 100)]).unwrap();
        let mut builder = RecordAckBuilder::new();

        assert!(builder
            .try_push_range(ack_range(95, 100), first_only.encoded_len())
            .unwrap());
        assert!(!builder
            .try_push_range(ack_range(90, 92), first_only.encoded_len())
            .unwrap());
        assert_eq!(builder.build().unwrap(), first_only);
    }

    #[test]
    fn builder_rejects_non_canonical_ranges() {
        let mut builder = RecordAckBuilder::new();
        assert!(builder
            .try_push_range(ack_range(95, 100), usize::MAX)
            .unwrap());
        assert_eq!(
            builder.try_push_range(ack_range(90, 95), usize::MAX),
            Err(RecordAckRangeError::NotCanonical)
        );
    }

    #[test]
    fn rejects_unsorted_ranges() {
        assert_eq!(
            RecordAck::from_ranges([ack_range(90, 92), ack_range(95, 100)]),
            Err(RecordAckRangeError::NotCanonical)
        );
    }

    #[test]
    fn rejects_touching_ranges() {
        assert_eq!(
            RecordAck::from_ranges([ack_range(10, 12), ack_range(7, 9)]),
            Err(RecordAckRangeError::NotCanonical)
        );
    }

    #[test]
    fn rejects_overlapping_ranges() {
        assert_eq!(
            RecordAck::from_ranges([ack_range(10, 12), ack_range(8, 11)]),
            Err(RecordAckRangeError::NotCanonical)
        );
    }

    #[test]
    fn contains_matches_range_membership() {
        let ack = RecordAck::from_ranges([
            ack_range(150, 163),
            ack_range(105, 110),
            ack_range(100, 100),
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
            RecordAck::from_ranges([ack_range(5, 4)]),
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
            RecordAck::decode_exact(encoded.as_slice()),
            Err(WireError::InvalidPayload)
        );
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        assert_eq!(
            RecordAck::decode_exact(&[][..]),
            Err(WireError::InvalidPayload)
        );

        let encoded = RecordAck::from_ranges([ack_range(42, 42)])
            .unwrap()
            .encode_vec();
        assert_eq!(
            RecordAck::decode_exact(&encoded[..encoded.len() - 1]),
            Err(WireError::InvalidPayload)
        );
    }
}
