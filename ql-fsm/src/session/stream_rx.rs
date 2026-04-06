use std::collections::VecDeque;

use super::range_set::RangeSet;

/// reassembles one stream direction from out-of-order byte ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRx {
    start_offset: u64,
    bytes: VecDeque<u8>,
    missing: RangeSet,
    final_offset: Option<u64>,
    max_buffered: usize,
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
}

#[derive(Debug, Clone)]
pub struct StreamReadIter<'a> {
    front: Option<&'a [u8]>,
    back: Option<&'a [u8]>,
}

impl StreamRx {
    pub fn new(max_buffered: usize) -> Self {
        Self::with_start_offset(0, max_buffered)
    }

    pub fn with_start_offset(start_offset: u64, max_buffered: usize) -> Self {
        Self {
            start_offset,
            bytes: VecDeque::new(),
            missing: RangeSet::new(),
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

        match self.missing.peek_min() {
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
        self.ensure_buffered(end);
        #[cfg(test)]
        self.assert_valid_overlap(effective_offset, effective_bytes);
        self.write_bytes(effective_offset, effective_bytes);
        self.missing.remove(effective_offset..end);

        Ok(self.insert_outcome(was_complete, old_readable))
    }

    pub fn consume(&mut self, len: usize) {
        let readable = self.readable_len();
        debug_assert!(len <= readable, "consume beyond readable bytes");
        if len > readable {
            return;
        }

        self.bytes.drain(..len);
        self.start_offset = self.start_offset.saturating_add(len as u64);
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

    fn ensure_buffered(&mut self, end: u64) {
        let buffered_end = self.buffered_end_offset();
        if end <= buffered_end {
            return;
        }

        let additional = usize::try_from(end - buffered_end).expect("buffer growth exceeds usize");
        self.bytes.resize(self.bytes.len() + additional, 0);
        self.missing.insert(buffered_end..end);
    }

    #[cfg(test)]
    fn assert_valid_overlap(&self, offset: u64, bytes: &[u8]) {
        for (index, byte) in bytes.iter().copied().enumerate() {
            let absolute = offset + index as u64;
            let is_missing = self
                .missing
                .iter()
                .any(|range| range.start <= absolute && absolute < range.end);
            if is_missing {
                continue;
            }

            let index =
                usize::try_from(absolute - self.start_offset).expect("read index exceeds usize");

            assert_eq!(
                self.bytes[index], byte,
                "conflicting overlap at stream offset {absolute}"
            );
        }
    }

    fn write_bytes(&mut self, offset: u64, bytes: &[u8]) {
        let start = usize::try_from(offset - self.start_offset).expect("write index exceeds usize");
        let (front, back) = self.bytes.as_mut_slices();

        if start >= front.len() {
            let start = start - front.len();
            back[start..start + bytes.len()].copy_from_slice(bytes);
            return;
        }

        let front_len = (front.len() - start).min(bytes.len());
        front[start..start + front_len].copy_from_slice(&bytes[..front_len]);

        if front_len < bytes.len() {
            back[..bytes.len() - front_len].copy_from_slice(&bytes[front_len..]);
        }
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

#[cfg(test)]
mod tests {
    use super::{InsertOutcome, StreamRx, StreamRxError};

    pub fn copy_readable(rx: &StreamRx) -> Vec<u8> {
        let readable = rx.readable_len();
        let mut out = Vec::with_capacity(readable);
        for chunk in rx.bytes() {
            out.extend_from_slice(chunk);
        }
        out
    }

    #[test]
    fn contiguous_insert_becomes_readable_and_complete() {
        let mut rx = StreamRx::new(64);

        let outcome = rx.insert(0, true, b"hello").unwrap();

        assert_eq!(
            outcome,
            InsertOutcome {
                newly_readable_bytes: 5,
                became_complete: true,
            }
        );
        assert_eq!(rx.readable_len(), 5);
        assert_eq!(copy_readable(&rx), b"hello");
        assert_eq!(rx.final_offset, Some(5));
        assert!(rx.is_complete());
        assert!(rx.missing.is_empty());
    }

    #[test]
    fn out_of_order_insert_tracks_missing_ranges_until_gap_is_filled() {
        let mut rx = StreamRx::new(64);

        let first = rx.insert(5, true, b" world").unwrap();
        assert_eq!(
            first,
            InsertOutcome {
                newly_readable_bytes: 0,
                became_complete: false,
            }
        );
        assert_eq!(rx.missing.iter().collect::<Vec<_>>(), vec![0..5]);
        assert_eq!(rx.readable_len(), 0);

        let second = rx.insert(0, false, b"hello").unwrap();
        assert_eq!(
            second,
            InsertOutcome {
                newly_readable_bytes: 11,
                became_complete: true,
            }
        );
        assert_eq!(copy_readable(&rx), b"hello world");
        assert!(rx.missing.is_empty());
        assert!(rx.is_complete());
    }

    #[test]
    fn duplicate_insert_is_ignored_if_bytes_match() {
        let mut rx = StreamRx::new(64);

        rx.insert(0, false, b"hello").unwrap();
        let duplicate = rx.insert(0, false, b"hello").unwrap();

        assert_eq!(
            duplicate,
            InsertOutcome {
                newly_readable_bytes: 0,
                became_complete: false,
            }
        );
        assert_eq!(copy_readable(&rx), b"hello");
    }

    #[test]
    #[should_panic(expected = "conflicting overlap at stream offset 3")]
    fn conflicting_overlap_panics_in_test_builds() {
        let mut rx = StreamRx::new(64);

        rx.insert(0, false, b"abcdef").unwrap();
        rx.insert(3, false, b"xyz").unwrap();
    }

    #[test]
    fn consume_advances_start_offset_and_trims_old_prefix() {
        let mut rx = StreamRx::new(64);

        rx.insert(0, false, b"abcd").unwrap();
        rx.consume(2);
        assert_eq!(rx.start_offset(), 2);
        assert_eq!(copy_readable(&rx), b"cd");

        let outcome = rx.insert(1, true, b"bcde").unwrap();
        assert_eq!(
            outcome,
            InsertOutcome {
                newly_readable_bytes: 1,
                became_complete: true,
            }
        );
        assert_eq!(copy_readable(&rx), b"cde");
        assert_eq!(rx.final_offset, Some(5));
        assert!(rx.is_complete());
    }

    #[test]
    fn insert_can_fill_multiple_gaps_without_rebuilding_state() {
        let mut rx = StreamRx::new(64);

        rx.insert(0, false, b"ab").unwrap();
        rx.insert(4, false, b"ef").unwrap();
        rx.insert(8, true, b"ij").unwrap();

        assert_eq!(rx.missing.iter().collect::<Vec<_>>(), vec![2..4, 6..8]);

        let outcome = rx.insert(2, false, b"cdefgh").unwrap();

        assert_eq!(
            outcome,
            InsertOutcome {
                newly_readable_bytes: 8,
                became_complete: true,
            }
        );
        assert!(rx.missing.is_empty());

        assert_eq!(copy_readable(&rx), b"abcdefghij");
        assert!(rx.is_complete());
    }

    #[test]
    fn heavily_fragmented_inserts_stay_valid() {
        let mut rx = StreamRx::new(64);

        rx.insert(1, false, b"b").unwrap();
        rx.insert(3, false, b"d").unwrap();
        rx.insert(5, false, b"f").unwrap();
        rx.insert(7, false, b"h").unwrap();
        rx.insert(9, true, b"j").unwrap();

        assert_eq!(
            rx.missing.iter().collect::<Vec<_>>(),
            vec![0..1, 2..3, 4..5, 6..7, 8..9]
        );

        let outcome = rx.insert(0, false, b"abcdefghi").unwrap();
        assert_eq!(
            outcome,
            InsertOutcome {
                newly_readable_bytes: 10,
                became_complete: true,
            }
        );
        assert_eq!(copy_readable(&rx), b"abcdefghij");
        assert!(rx.is_complete());
    }

    #[test]
    fn out_of_window_insert_is_rejected() {
        let mut rx = StreamRx::new(4);
        let error = rx.insert(5, false, b"a").unwrap_err();
        assert_eq!(error, StreamRxError::OutOfWindow);
    }
}
