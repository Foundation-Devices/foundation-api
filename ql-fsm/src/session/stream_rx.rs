use std::collections::VecDeque;

/// reassembles one stream direction from out-of-order byte ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRx<const MAX_MISSING_RANGES: usize = 8> {
    start_offset: u64,
    bytes: VecDeque<u8>,
    missing: MissingRanges<MAX_MISSING_RANGES>,
    final_offset: Option<u64>,
    max_buffered: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InsertOutcome {
    pub newly_readable_bytes: usize,
    pub became_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRxError {
    OffsetOverflow,
    OutOfWindow,
    InconsistentFinalOffset,
    FinalOffsetBeforeBufferedData,
    BeyondFinalOffset,
    ConflictingOverlap,
    ConsumeBeyondReadable,
    TooManyMissingRanges,
}

#[derive(Debug, Clone, Copy)]
pub struct StreamReadIter<'a> {
    front: Option<&'a [u8]>,
    back: Option<&'a [u8]>,
}

impl<const MAX_MISSING_RANGES: usize> StreamRx<MAX_MISSING_RANGES> {
    pub fn new(max_buffered: usize) -> Self {
        Self::with_start_offset(0, max_buffered)
    }

    pub fn with_start_offset(start_offset: u64, max_buffered: usize) -> Self {
        Self {
            start_offset,
            bytes: VecDeque::new(),
            missing: MissingRanges::new(),
            final_offset: None,
            max_buffered,
        }
    }

    pub fn start_offset(&self) -> u64 {
        self.start_offset
    }

    pub fn buffered_end_offset(&self) -> u64 {
        self.start_offset + self.bytes.len() as u64
    }

    pub fn max_buffered(&self) -> usize {
        self.max_buffered
    }

    pub fn readable_len(&self) -> usize {
        if self.bytes.is_empty() {
            return 0;
        }

        match self.missing.first() {
            Some(range) if range.start <= self.start_offset => 0,
            Some(range) => usize::try_from(range.start - self.start_offset)
                .expect("readable prefix exceeds usize"),
            None => self.bytes.len(),
        }
    }

    pub fn bytes(&self) -> StreamReadIter<'_> {
        let readable = self.readable_len();
        if readable == 0 {
            return StreamReadIter {
                front: None,
                back: None,
            };
        }

        let (front, back) = self.bytes.as_slices();
        if readable <= front.len() {
            StreamReadIter {
                front: Some(&front[..readable]),
                back: None,
            }
        } else {
            StreamReadIter {
                front: Some(front),
                back: Some(&back[..readable - front.len()]),
            }
        }
    }

    #[cfg(test)]
    pub fn copy_readable(&self) -> Vec<u8> {
        let readable = self.readable_len();
        let mut out = Vec::with_capacity(readable);
        for chunk in self.bytes() {
            out.extend_from_slice(chunk);
        }
        out
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.final_offset, Some(final_offset) if final_offset == self.buffered_end_offset())
            && self.missing.is_empty()
    }

    pub fn insert(
        &mut self,
        offset: u64,
        fin: bool,
        bytes: &[u8],
    ) -> Result<InsertOutcome, StreamRxError> {
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or(StreamRxError::OffsetOverflow)?;

        let was_complete = self.is_complete();
        let old_readable = self.readable_len();

        if fin {
            self.set_or_validate_final_offset(end)?;
        }
        if let Some(final_offset) = self.final_offset {
            if end > final_offset {
                return Err(StreamRxError::BeyondFinalOffset);
            }
        }

        if bytes.is_empty() || end <= self.start_offset {
            return Ok(self.insert_outcome(was_complete, old_readable));
        }

        let effective_offset = offset.max(self.start_offset);
        let trim_front =
            usize::try_from(effective_offset - offset).expect("front trim exceeds usize");
        let effective_bytes = &bytes[trim_front..];
        if effective_bytes.is_empty() {
            return Ok(self.insert_outcome(was_complete, old_readable));
        }

        self.ensure_within_window(end)?;
        self.ensure_buffered(end)?;
        self.validate_overlap(effective_offset, effective_bytes)?;
        self.write_bytes(effective_offset, effective_bytes);
        self.subtract_missing_range(effective_offset, end)?;

        Ok(self.insert_outcome(was_complete, old_readable))
    }

    pub fn consume(&mut self, len: usize) -> Result<(), StreamRxError> {
        let readable = self.readable_len();
        if len > readable {
            return Err(StreamRxError::ConsumeBeyondReadable);
        }

        self.bytes.drain(..len);
        self.start_offset = self.start_offset.saturating_add(len as u64);
        Ok(())
    }

    fn insert_outcome(&self, was_complete: bool, old_readable: usize) -> InsertOutcome {
        InsertOutcome {
            newly_readable_bytes: self.readable_len().saturating_sub(old_readable),
            became_complete: !was_complete && self.is_complete(),
        }
    }

    fn set_or_validate_final_offset(&mut self, final_offset: u64) -> Result<(), StreamRxError> {
        if let Some(existing) = self.final_offset {
            return if existing == final_offset {
                Ok(())
            } else {
                Err(StreamRxError::InconsistentFinalOffset)
            };
        }

        let buffered_end = self.buffered_end_offset();
        if final_offset < buffered_end {
            return Err(StreamRxError::FinalOffsetBeforeBufferedData);
        }

        self.final_offset = Some(final_offset);
        Ok(())
    }

    fn ensure_within_window(&self, end: u64) -> Result<(), StreamRxError> {
        let attempted = end.saturating_sub(self.start_offset);
        if attempted > self.max_buffered as u64 {
            return Err(StreamRxError::OutOfWindow);
        }
        Ok(())
    }

    fn ensure_buffered(&mut self, end: u64) -> Result<(), StreamRxError> {
        let buffered_end = self.buffered_end_offset();
        if end <= buffered_end {
            return Ok(());
        }

        let additional = usize::try_from(end - buffered_end).expect("buffer growth exceeds usize");
        self.bytes.resize(self.bytes.len() + additional, 0);
        self.push_missing_range(MissingRange {
            start: buffered_end,
            end,
        })
    }

    fn push_missing_range(&mut self, range: MissingRange) -> Result<(), StreamRxError> {
        if range.start >= range.end {
            return Ok(());
        }

        if let Some(last) = self.missing.last_mut() {
            if last.end >= range.start {
                last.end = last.end.max(range.end);
                return Ok(());
            }
        }

        self.missing.push(range)
    }

    fn validate_overlap(&self, offset: u64, bytes: &[u8]) -> Result<(), StreamRxError> {
        let mut gap_index = self.first_gap_index_after(offset);

        for (index, byte) in bytes.iter().copied().enumerate() {
            let absolute = offset + index as u64;

            while gap_index < self.missing.len() && self.missing[gap_index].end <= absolute {
                gap_index += 1;
            }

            let is_missing = gap_index < self.missing.len()
                && self.missing[gap_index].start <= absolute
                && absolute < self.missing[gap_index].end;
            if is_missing {
                continue;
            }

            if self.byte_at(absolute) != byte {
                return Err(StreamRxError::ConflictingOverlap);
            }
        }

        Ok(())
    }

    fn write_bytes(&mut self, offset: u64, bytes: &[u8]) {
        let start_index =
            usize::try_from(offset - self.start_offset).expect("write index exceeds usize");
        for (index, byte) in bytes.iter().copied().enumerate() {
            self.bytes[start_index + index] = byte;
        }
    }

    fn subtract_missing_range(&mut self, start: u64, end: u64) -> Result<(), StreamRxError> {
        let first = self.first_gap_index_after(start);
        if first == self.missing.len() || self.missing[first].start >= end {
            return Ok(());
        }

        let mut last_exclusive = first;
        while last_exclusive < self.missing.len() && self.missing[last_exclusive].start < end {
            last_exclusive += 1;
        }

        let last = last_exclusive - 1;
        let keep_left = self.missing[first].start < start;
        let keep_right = self.missing[last].end > end;

        if first == last {
            let original = self.missing[first];
            match (keep_left, keep_right) {
                (true, true) => {
                    self.missing[first].end = start;
                    self.missing.insert(
                        first + 1,
                        MissingRange {
                            start: end,
                            end: original.end,
                        },
                    )?;
                }
                (true, false) => {
                    self.missing[first].end = start;
                }
                (false, true) => {
                    self.missing[first].start = end;
                }
                (false, false) => {
                    self.missing.remove(first);
                }
            }
            return Ok(());
        }

        match (keep_left, keep_right) {
            (true, true) => {
                self.missing[first].end = start;
                self.missing[last].start = end;
                self.missing.drain(first + 1..last);
            }
            (true, false) => {
                self.missing[first].end = start;
                self.missing.drain(first + 1..last_exclusive);
            }
            (false, true) => {
                self.missing[last].start = end;
                self.missing.drain(first..last);
            }
            (false, false) => {
                self.missing.drain(first..last_exclusive);
            }
        }

        Ok(())
    }

    fn first_gap_index_after(&self, offset: u64) -> usize {
        self.missing
            .as_slice()
            .partition_point(|range| range.end <= offset)
    }

    fn byte_at(&self, offset: u64) -> u8 {
        let index = usize::try_from(offset - self.start_offset).expect("read index exceeds usize");
        self.bytes[index]
    }
}

impl<'a> Iterator for StreamReadIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(front) = self.front.take() {
            if !front.is_empty() {
                return Some(front);
            }
        }

        if let Some(back) = self.back.take() {
            if !back.is_empty() {
                return Some(back);
            }
        }

        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MissingRanges<const N: usize> {
    ranges: [MissingRange; N],
    len: usize,
}

impl<const N: usize> MissingRanges<N> {
    fn new() -> Self {
        Self {
            ranges: [MissingRange { start: 0, end: 0 }; N],
            len: 0,
        }
    }

    fn as_slice(&self) -> &[MissingRange] {
        &self.ranges[..self.len]
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn len(&self) -> usize {
        self.len
    }

    fn first(&self) -> Option<&MissingRange> {
        self.as_slice().first()
    }

    fn last_mut(&mut self) -> Option<&mut MissingRange> {
        if self.len == 0 {
            None
        } else {
            Some(&mut self.ranges[self.len - 1])
        }
    }

    fn push(&mut self, range: MissingRange) -> Result<(), StreamRxError> {
        if self.len == N {
            return Err(StreamRxError::TooManyMissingRanges);
        }
        self.ranges[self.len] = range;
        self.len += 1;
        Ok(())
    }

    fn insert(&mut self, index: usize, range: MissingRange) -> Result<(), StreamRxError> {
        if self.len == N {
            return Err(StreamRxError::TooManyMissingRanges);
        }
        for i in (index..self.len).rev() {
            self.ranges[i + 1] = self.ranges[i];
        }
        self.ranges[index] = range;
        self.len += 1;
        Ok(())
    }

    fn remove(&mut self, index: usize) -> MissingRange {
        let removed = self.ranges[index];
        for i in index + 1..self.len {
            self.ranges[i - 1] = self.ranges[i];
        }
        self.len -= 1;
        self.ranges[self.len] = MissingRange { start: 0, end: 0 };
        removed
    }

    fn drain(&mut self, range: std::ops::Range<usize>) {
        let count = range.end - range.start;
        if count == 0 {
            return;
        }

        for i in range.end..self.len {
            self.ranges[i - count] = self.ranges[i];
        }
        for i in self.len - count..self.len {
            self.ranges[i] = MissingRange { start: 0, end: 0 };
        }
        self.len -= count;
    }
}

impl<const N: usize> std::ops::Index<usize> for MissingRanges<N> {
    type Output = MissingRange;

    fn index(&self, index: usize) -> &Self::Output {
        &self.as_slice()[index]
    }
}

impl<const N: usize> std::ops::IndexMut<usize> for MissingRanges<N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.ranges[index]
    }
}

#[cfg(test)]
mod tests {
    use super::{InsertOutcome, MissingRange, StreamRx, StreamRxError};

    #[test]
    fn contiguous_insert_becomes_readable_and_complete() {
        let mut rx = StreamRx::<8>::new(64);

        let outcome = rx.insert(0, true, b"hello").unwrap();

        assert_eq!(
            outcome,
            InsertOutcome {
                newly_readable_bytes: 5,
                became_complete: true,
            }
        );
        assert_eq!(rx.readable_len(), 5);
        assert_eq!(rx.copy_readable(), b"hello");
        assert_eq!(rx.final_offset, Some(5));
        assert!(rx.is_complete());
        assert!(rx.missing.is_empty());
    }

    #[test]
    fn out_of_order_insert_tracks_missing_ranges_until_gap_is_filled() {
        let mut rx = StreamRx::<8>::new(64);

        let first = rx.insert(5, true, b" world").unwrap();
        assert_eq!(
            first,
            InsertOutcome {
                newly_readable_bytes: 0,
                became_complete: false,
            }
        );
        assert_eq!(rx.missing.as_slice(), &[MissingRange { start: 0, end: 5 }]);
        assert_eq!(rx.readable_len(), 0);

        let second = rx.insert(0, false, b"hello").unwrap();
        assert_eq!(
            second,
            InsertOutcome {
                newly_readable_bytes: 11,
                became_complete: true,
            }
        );
        assert_eq!(rx.copy_readable(), b"hello world");
        assert!(rx.missing.is_empty());
        assert!(rx.is_complete());
    }

    #[test]
    fn duplicate_insert_is_ignored_if_bytes_match() {
        let mut rx = StreamRx::<8>::new(64);

        rx.insert(0, false, b"hello").unwrap();
        let duplicate = rx.insert(0, false, b"hello").unwrap();

        assert_eq!(
            duplicate,
            InsertOutcome {
                newly_readable_bytes: 0,
                became_complete: false,
            }
        );
        assert_eq!(rx.copy_readable(), b"hello");
    }

    #[test]
    fn conflicting_overlap_is_rejected() {
        let mut rx = StreamRx::<8>::new(64);

        rx.insert(0, false, b"abcdef").unwrap();
        let error = rx.insert(3, false, b"xyz").unwrap_err();

        assert_eq!(error, StreamRxError::ConflictingOverlap);
    }

    #[test]
    fn consume_advances_start_offset_and_trims_old_prefix() {
        let mut rx = StreamRx::<8>::new(64);

        rx.insert(0, false, b"abcd").unwrap();
        rx.consume(2).unwrap();
        assert_eq!(rx.start_offset(), 2);
        assert_eq!(rx.copy_readable(), b"cd");

        let outcome = rx.insert(1, true, b"bcde").unwrap();
        assert_eq!(
            outcome,
            InsertOutcome {
                newly_readable_bytes: 1,
                became_complete: true,
            }
        );
        assert_eq!(rx.copy_readable(), b"cde");
        assert_eq!(rx.final_offset, Some(5));
        assert!(rx.is_complete());
    }

    #[test]
    fn insert_rejects_when_missing_range_budget_is_exhausted() {
        let mut rx = StreamRx::<2>::new(64);

        rx.insert(1, false, b"a").unwrap();
        rx.insert(3, false, b"b").unwrap();
        let error = rx.insert(5, false, b"c").unwrap_err();

        assert_eq!(error, StreamRxError::TooManyMissingRanges);
    }

    #[test]
    fn insert_can_fill_multiple_gaps_without_rebuilding_state() {
        let mut rx = StreamRx::<8>::new(64);

        rx.insert(0, false, b"ab").unwrap();
        rx.insert(4, false, b"ef").unwrap();
        rx.insert(8, true, b"ij").unwrap();

        assert_eq!(
            rx.missing.as_slice(),
            &[
                MissingRange { start: 2, end: 4 },
                MissingRange { start: 6, end: 8 },
            ]
        );

        let outcome = rx.insert(2, false, b"cdefgh").unwrap();

        assert_eq!(
            outcome,
            InsertOutcome {
                newly_readable_bytes: 8,
                became_complete: true,
            }
        );
        assert!(rx.missing.is_empty());
        assert_eq!(rx.copy_readable(), b"abcdefghij");
        assert!(rx.is_complete());
    }
}
