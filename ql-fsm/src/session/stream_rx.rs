use std::collections::{btree_map, BTreeMap};

use bytes::{Buf, Bytes};

/// reassembles one stream direction from out-of-order byte ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRx {
    start_offset: u64,
    chunks: BTreeMap<u64, Bytes>,
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

impl StreamRx {
    pub fn new(max_buffered: usize) -> Self {
        Self::with_start_offset(0, max_buffered)
    }

    pub fn with_start_offset(start_offset: u64, max_buffered: usize) -> Self {
        Self {
            start_offset,
            chunks: BTreeMap::new(),
            final_offset: None,
            max_buffered,
        }
    }

    pub fn start_offset(&self) -> u64 {
        self.start_offset
    }

    pub fn buffered_end_offset(&self) -> u64 {
        self.chunks
            .last_key_value()
            .map_or(self.start_offset, |(&offset, bytes)| {
                offset + bytes.len() as u64
            })
    }

    pub fn max_buffered(&self) -> usize {
        self.max_buffered
    }

    pub fn readable_len(&self) -> usize {
        let mut cursor = self.start_offset;
        for (&offset, bytes) in self.chunks.range(self.start_offset..) {
            if offset > cursor {
                break;
            }

            let end = offset + bytes.len() as u64;
            if end > cursor {
                cursor = end;
            }
        }

        usize::try_from(cursor - self.start_offset).expect("readable prefix exceeds usize")
    }

    pub fn bytes(&self) -> StreamReadIter<'_> {
        StreamReadIter {
            inner: self.chunks.range(self.start_offset..),
            cursor: self.start_offset,
            remaining: self.readable_len(),
        }
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.final_offset, Some(final_offset)
            if final_offset == self.buffered_end_offset()
                && final_offset == self.start_offset + self.readable_len() as u64)
    }

    pub fn insert(
        &mut self,
        offset: u64,
        fin: bool,
        mut bytes: Bytes,
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
        bytes.advance(trim_front);
        if bytes.is_empty() {
            return Ok(self.insert_outcome(was_complete, old_readable));
        }

        let effective_end = effective_offset + bytes.len() as u64;
        self.ensure_within_window(effective_end)?;
        self.insert_chunk(effective_offset, bytes);

        Ok(self.insert_outcome(was_complete, old_readable))
    }

    pub fn consume(&mut self, len: usize) {
        let readable = self.readable_len();
        debug_assert!(len <= readable, "consume beyond readable bytes");
        if len > readable {
            return;
        }

        let new_start = self.start_offset.saturating_add(len as u64);
        while let Some((&offset, bytes)) = self.chunks.first_key_value() {
            let end = offset + bytes.len() as u64;
            if end <= new_start {
                self.chunks.pop_first();
                continue;
            }
            if offset < new_start {
                let (offset, mut bytes) = self.chunks.pop_first().unwrap();
                bytes.advance(usize::try_from(new_start - offset).expect("trim exceeds usize"));
                self.chunks.insert(new_start, bytes);
            }
            break;
        }

        self.start_offset = new_start;
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

    fn insert_chunk(&mut self, mut offset: u64, mut bytes: Bytes) {
        if bytes.is_empty() {
            return;
        }

        if let Some((&existing_offset, existing)) = self.chunks.range(..offset).next_back() {
            let existing_end = existing_offset + existing.len() as u64;
            if existing_end > offset {
                let overlap =
                    usize::try_from((existing_end - offset).min(bytes.len() as u64)).unwrap();
                bytes.advance(overlap);
                offset += overlap as u64;
            }
        }

        if bytes.is_empty() {
            return;
        }

        let end = offset + bytes.len() as u64;
        let overlapping = self
            .chunks
            .range(offset..end)
            .map(|(&chunk_offset, _)| chunk_offset)
            .collect::<Vec<_>>();

        for chunk_offset in overlapping {
            let chunk_end = chunk_offset + self.chunks[&chunk_offset].len() as u64;

            if chunk_offset > offset {
                let len = usize::try_from(chunk_offset - offset).expect("gap exceeds usize");
                self.chunks.insert(offset, bytes.slice(..len));
                bytes.advance(len);
                offset = chunk_offset;
            }

            let overlap = usize::try_from((chunk_end - offset).min(bytes.len() as u64)).unwrap();
            bytes.advance(overlap);
            offset += overlap as u64;

            if bytes.is_empty() {
                return;
            }
        }

        self.chunks.insert(offset, bytes);
    }
}

#[derive(Debug, Clone)]
pub struct StreamReadIter<'a> {
    inner: btree_map::Range<'a, u64, Bytes>,
    cursor: u64,
    remaining: usize,
}

impl Iterator for StreamReadIter<'_> {
    type Item = Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining > 0 {
            let (&offset, bytes) = self.inner.next()?;
            if offset > self.cursor {
                self.remaining = 0;
                return None;
            }

            let skip = usize::try_from(self.cursor.saturating_sub(offset))
                .expect("read cursor exceeds usize");
            if skip >= bytes.len() {
                continue;
            }

            let len = (bytes.len() - skip).min(self.remaining);
            self.remaining -= len;
            self.cursor += len as u64;
            return Some(bytes.slice(skip..skip + len));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{InsertOutcome, StreamRx, StreamRxError};

    pub fn copy_readable(rx: &StreamRx) -> Vec<u8> {
        let readable = rx.readable_len();
        let mut out = Vec::with_capacity(readable);
        for chunk in rx.bytes() {
            out.extend_from_slice(&chunk);
        }
        out
    }

    fn bytes(bytes: &'static [u8]) -> Bytes {
        Bytes::from_static(bytes)
    }

    #[test]
    fn contiguous_insert_becomes_readable_and_complete() {
        let mut rx = StreamRx::new(64);

        let outcome = rx.insert(0, true, bytes(b"hello")).unwrap();

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
    }

    #[test]
    fn out_of_order_insert_tracks_gap_until_prefix_is_filled() {
        let mut rx = StreamRx::new(64);

        let first = rx.insert(5, true, bytes(b" world")).unwrap();
        assert_eq!(
            first,
            InsertOutcome {
                newly_readable_bytes: 0,
                became_complete: false,
            }
        );
        assert_eq!(rx.readable_len(), 0);

        let second = rx.insert(0, false, bytes(b"hello")).unwrap();
        assert_eq!(
            second,
            InsertOutcome {
                newly_readable_bytes: 11,
                became_complete: true,
            }
        );
        assert_eq!(copy_readable(&rx), b"hello world");
        assert!(rx.is_complete());
    }

    #[test]
    fn duplicate_insert_is_ignored_if_bytes_match() {
        let mut rx = StreamRx::new(64);

        rx.insert(0, false, bytes(b"hello")).unwrap();
        let duplicate = rx.insert(0, false, bytes(b"hello")).unwrap();

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
    fn consume_advances_start_offset_and_trims_old_prefix() {
        let mut rx = StreamRx::new(64);

        rx.insert(0, false, bytes(b"abcd")).unwrap();
        rx.consume(2);
        assert_eq!(rx.start_offset(), 2);
        assert_eq!(copy_readable(&rx), b"cd");

        let outcome = rx.insert(1, true, bytes(b"bcde")).unwrap();
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

        rx.insert(0, false, bytes(b"ab")).unwrap();
        rx.insert(4, false, bytes(b"ef")).unwrap();
        rx.insert(8, true, bytes(b"ij")).unwrap();

        let outcome = rx.insert(2, false, bytes(b"cdefgh")).unwrap();

        assert_eq!(
            outcome,
            InsertOutcome {
                newly_readable_bytes: 8,
                became_complete: true,
            }
        );

        assert_eq!(copy_readable(&rx), b"abcdefghij");
        assert!(rx.is_complete());
    }

    #[test]
    fn heavily_fragmented_inserts_stay_valid() {
        let mut rx = StreamRx::new(64);

        rx.insert(1, false, bytes(b"b")).unwrap();
        rx.insert(3, false, bytes(b"d")).unwrap();
        rx.insert(5, false, bytes(b"f")).unwrap();
        rx.insert(7, false, bytes(b"h")).unwrap();
        rx.insert(9, true, bytes(b"j")).unwrap();

        let outcome = rx.insert(0, false, bytes(b"abcdefghi")).unwrap();
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
        let error = rx.insert(5, false, bytes(b"a")).unwrap_err();
        assert_eq!(error, StreamRxError::OutOfWindow);
    }
}
