use std::{collections::VecDeque, ops::Range};

use bytes::{Buf, Bytes};
use ql_wire::BufView;

use super::range_set::RangeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamTx {
    chunks: VecDeque<Bytes>,
    buffered_len: usize,
    base_offset: u64,
    unsent: u64,
    acked: RangeSet,
    retransmits: RangeSet,
    final_offset: Option<TrackedFinalOffset>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrackedFinalOffset {
    offset: u64,
    state: SendState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendState {
    Unsent,
    Sent,
    Lost,
    Acked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamTxRange {
    pub offset: u64,
    pub len: usize,
    pub fin: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct StreamTxBytes<'a> {
    inner: &'a VecDeque<Bytes>,
    offset: usize,
    len: usize,
}

pub struct StreamTxBuf<'a> {
    inner: std::collections::vec_deque::Iter<'a, Bytes>,
    skip: usize,
    remaining: usize,
    current: &'a [u8],
}

impl BufView for StreamTxBytes<'_> {
    type Buf<'a>
        = StreamTxBuf<'a>
    where
        Self: 'a;

    fn buf(&self) -> Self::Buf<'_> {
        let mut buf = StreamTxBuf {
            inner: self.inner.iter(),
            skip: self.offset,
            remaining: self.len,
            current: &[],
        };
        buf.refill();
        buf
    }
}

impl<'a> StreamTxBuf<'a> {
    fn refill(&mut self) {
        if self.remaining == 0 {
            self.current = &[];
            return;
        }

        while let Some(chunk) = self.inner.next() {
            if self.skip >= chunk.len() {
                self.skip -= chunk.len();
                continue;
            }

            let chunk = &chunk[self.skip..];
            self.skip = 0;
            if chunk.is_empty() {
                continue;
            }

            let len = chunk.len().min(self.remaining);
            self.current = &chunk[..len];
            return;
        }

        self.current = &[];
    }
}

impl Buf for StreamTxBuf<'_> {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        self.current
    }

    fn advance(&mut self, cnt: usize) {
        let remaining = self.remaining;
        assert!(
            cnt <= remaining,
            "cannot advance past remaining bytes: {cnt} > {remaining}",
        );

        self.remaining -= cnt;
        let mut cnt = cnt;
        while cnt > 0 {
            if cnt < self.current.len() {
                self.current = &self.current[cnt..];
                return;
            }

            cnt -= self.current.len();
            self.refill();
        }

        if self.remaining == 0 {
            self.current = &[];
        }
    }
}

impl StreamTx {
    pub fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
            buffered_len: 0,
            base_offset: 0,
            unsent: 0,
            acked: RangeSet::new(),
            retransmits: RangeSet::new(),
            final_offset: None,
        }
    }

    pub fn buffered_len(&self) -> usize {
        self.buffered_len
    }

    pub fn end_offset(&self) -> u64 {
        self.base_offset + self.buffered_len as u64
    }

    pub fn is_empty(&self) -> bool {
        self.buffered_len == 0 && self.final_offset.is_none()
    }

    pub fn append(&mut self, bytes: Bytes) {
        if bytes.is_empty() {
            return;
        }

        self.buffered_len += bytes.len();
        self.chunks.push_back(bytes);
    }

    pub fn queue_fin(&mut self) {
        self.final_offset = Some(TrackedFinalOffset {
            offset: self.end_offset(),
            state: SendState::Unsent,
        });
    }

    pub fn poll_transmit(
        &mut self,
        max_payload: usize,
        peer_max_offset: u64,
    ) -> Option<StreamTxRange> {
        // TODO: coalesce a lost range with contiguous unsent tail bytes when they fit in the same
        // transmit budget. That would let a repacked record send one larger StreamData frame
        // instead of retransmitting the lost prefix first and the new tail later.
        if let Some(range) = self.retransmits.peek_min() {
            let end = range
                .end
                .min(range.start.saturating_add(max_payload as u64))
                .min(peer_max_offset);
            if end > range.start {
                let range = self.retransmits.pop_min().unwrap();
                if end < range.end {
                    self.retransmits.insert(end..range.end);
                }
                return Some(StreamTxRange {
                    offset: range.start,
                    len: usize::try_from(end - range.start).unwrap(),
                    fin: self.poll_fin(end),
                });
            }
        }

        if self.unsent < self.end_offset() {
            let end = self
                .end_offset()
                .min(self.unsent.saturating_add(max_payload as u64))
                .min(peer_max_offset);
            if end > self.unsent {
                let start = self.unsent;
                self.unsent = end;
                return Some(StreamTxRange {
                    offset: start,
                    len: usize::try_from(end - start).unwrap(),
                    fin: self.poll_fin(end),
                });
            }
        }

        let final_offset = self.final_offset.filter(|final_offset| {
            matches!(final_offset.state, SendState::Lost | SendState::Unsent)
                && final_offset.offset <= peer_max_offset
        })?;
        self.final_offset.as_mut().unwrap().state = SendState::Sent;
        Some(StreamTxRange {
            offset: final_offset.offset,
            len: 0,
            fin: true,
        })
    }

    pub fn ranged_bytes(&self, range: StreamTxRange) -> StreamTxBytes<'_> {
        let offset = usize::try_from(range.offset - self.base_offset).unwrap();
        let len = range.len.min(self.buffered_len.saturating_sub(offset));
        StreamTxBytes {
            inner: &self.chunks,
            offset,
            len,
        }
    }

    pub fn retransmit(&mut self, range: StreamTxRange) {
        if let Some(range) = self.clamp_sent_range(range.offset, range.len) {
            Self::insert_not_acked(&self.acked, &mut self.retransmits, range);
        }
        if range.fin {
            self.mark_fin_lost();
        }
    }

    pub fn ack(&mut self, range: StreamTxRange) {
        if let Some(range) = self.clamp_buffered_range(range.offset, range.len) {
            self.acked.insert(range.clone());
            self.retransmits.remove(range);
            self.trim_acked_prefix();
        }
        if range.fin {
            if let Some(final_offset) = self.final_offset.as_mut() {
                final_offset.state = SendState::Acked;
            }
        }
        self.trim_acked_fin();
    }

    pub fn clear(&mut self) {
        self.chunks.clear();
        self.buffered_len = 0;
        self.unsent = self.base_offset;
        self.acked = RangeSet::new();
        self.retransmits = RangeSet::new();
        self.final_offset = None;
    }

    fn clamp_buffered_range(&self, offset: u64, len: usize) -> Option<Range<u64>> {
        if len == 0 {
            return None;
        }
        let start = offset.max(self.base_offset);
        let end = offset.saturating_add(len as u64).min(self.end_offset());
        (start < end).then_some(start..end)
    }

    fn clamp_sent_range(&self, offset: u64, len: usize) -> Option<Range<u64>> {
        if len == 0 {
            return None;
        }
        let start = offset.max(self.base_offset);
        let end = offset.saturating_add(len as u64).min(self.unsent);
        (start < end).then_some(start..end)
    }

    fn insert_not_acked(acked_set: &RangeSet, target: &mut RangeSet, range: Range<u64>) {
        let mut cursor = range.start;
        for acked in acked_set.iter() {
            if acked.end <= cursor {
                continue;
            }
            if acked.start >= range.end {
                break;
            }
            if cursor < acked.start {
                target.insert(cursor..acked.start.min(range.end));
            }
            cursor = cursor.max(acked.end);
            if cursor >= range.end {
                break;
            }
        }
        if cursor < range.end {
            target.insert(cursor..range.end);
        }
    }

    fn poll_fin(&mut self, offset: u64) -> bool {
        let Some(final_offset) = self.final_offset.as_mut() else {
            return false;
        };
        if matches!(final_offset.state, SendState::Lost | SendState::Unsent)
            && final_offset.offset == offset
        {
            final_offset.state = SendState::Sent;
            true
        } else {
            false
        }
    }

    fn mark_fin_lost(&mut self) {
        if let Some(final_offset) = self.final_offset.as_mut() {
            if final_offset.state != SendState::Acked {
                final_offset.state = SendState::Lost;
            }
        }
    }

    fn trim_acked_prefix(&mut self) {
        while self.acked.min() == Some(self.base_offset) {
            let prefix = self.acked.pop_min().unwrap();
            let mut to_advance = usize::try_from(prefix.end - prefix.start).unwrap();
            self.buffered_len -= to_advance;
            while to_advance > 0 {
                let front = self
                    .chunks
                    .front_mut()
                    .expect("expected buffered chunks for acked prefix");
                if front.len() <= to_advance {
                    to_advance -= front.len();
                    self.chunks.pop_front();
                } else {
                    front.advance(to_advance);
                    to_advance = 0;
                }
            }
            self.base_offset = prefix.end;
        }
    }

    fn trim_acked_fin(&mut self) {
        if self.final_offset.is_some_and(|final_offset| {
            final_offset.state == SendState::Acked
                && final_offset.offset == self.base_offset
                && self.buffered_len == 0
        }) {
            self.final_offset = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{StreamTx, StreamTxRange};

    #[test]
    fn append_tracks_unsent_tail() {
        let mut tx = StreamTx::new();
        tx.append(Bytes::from_static(b"abc"));
        tx.append(Bytes::from_static(b"de"));

        assert_eq!(
            tx.poll_transmit(8, u64::MAX),
            Some(StreamTxRange {
                offset: 0,
                len: 5,
                fin: false,
            })
        );
    }

    #[test]
    fn lost_range_is_selected_before_unsent_tail() {
        let mut tx = StreamTx::new();
        tx.append(Bytes::from_static(b"abcdef"));

        let first = tx.poll_transmit(3, u64::MAX).unwrap();
        tx.retransmit(first);

        assert_eq!(
            tx.poll_transmit(3, u64::MAX),
            Some(StreamTxRange {
                offset: 0,
                len: 3,
                fin: false,
            })
        );
    }

    #[test]
    fn acked_prefix_is_trimmed() {
        let mut tx = StreamTx::new();
        tx.append(Bytes::from_static(b"abcdef"));

        let first = tx.poll_transmit(3, u64::MAX).unwrap();
        tx.ack(first);

        assert_eq!(
            tx.poll_transmit(3, u64::MAX),
            Some(StreamTxRange {
                offset: 3,
                len: 3,
                fin: false,
            })
        );
    }

    #[test]
    fn empty_fin_is_tracked_separately() {
        let mut tx = StreamTx::new();
        tx.queue_fin();

        let range = tx.poll_transmit(16, u64::MAX).unwrap();
        assert_eq!(
            range,
            StreamTxRange {
                offset: 0,
                len: 0,
                fin: true,
            }
        );

        tx.ack(range);
        assert!(tx.is_empty());
    }

    #[test]
    fn subrange_updates_split_merged_in_flight_segments() {
        let mut tx = StreamTx::new();
        tx.append(Bytes::from_static(b"abcdefghijkl"));

        let _first = tx.poll_transmit(4, u64::MAX).unwrap();
        let second = tx.poll_transmit(4, u64::MAX).unwrap();
        let _third = tx.poll_transmit(4, u64::MAX).unwrap();

        tx.retransmit(second);

        assert_eq!(
            tx.poll_transmit(4, u64::MAX),
            Some(StreamTxRange {
                offset: 4,
                len: 4,
                fin: false,
            })
        );
    }

    #[test]
    fn acked_subrange_is_not_reopened_by_stale_timeout() {
        let mut tx = StreamTx::new();
        tx.append(Bytes::from_static(b"abcdefghijklmnop"));

        let _first = tx.poll_transmit(4, u64::MAX).unwrap();
        let second = tx.poll_transmit(4, u64::MAX).unwrap();
        let third = tx.poll_transmit(4, u64::MAX).unwrap();
        let _fourth = tx.poll_transmit(4, u64::MAX).unwrap();

        tx.ack(second);
        tx.retransmit(second);
        tx.retransmit(third);

        assert_eq!(
            tx.poll_transmit(4, u64::MAX),
            Some(StreamTxRange {
                offset: 8,
                len: 4,
                fin: false,
            })
        );
    }
}
