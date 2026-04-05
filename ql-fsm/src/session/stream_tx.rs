use std::collections::VecDeque;

use ql_wire::RangedByteChunks;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamTx {
    bytes: VecDeque<u8>,
    base_offset: u64,
    segments: VecDeque<SendSegment>,
    final_offset: Option<TrackedFinalOffset>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrackedFinalOffset {
    offset: u64,
    state: SendState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SendSegment {
    offset: u64,
    len: usize,
    state: SendState,
}

impl SendSegment {
    fn end_offset(&self) -> u64 {
        self.offset + self.len as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendState {
    Unsent,
    InFlight,
    Lost,
    Acked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamTxRange {
    pub offset: u64,
    pub len: usize,
    pub fin: bool,
}

impl StreamTx {
    pub fn new() -> Self {
        Self {
            bytes: VecDeque::new(),
            base_offset: 0,
            segments: VecDeque::new(),
            final_offset: None,
        }
    }

    pub fn buffered_len(&self) -> usize {
        self.bytes.len()
    }

    pub fn end_offset(&self) -> u64 {
        self.base_offset + self.bytes.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty() && self.segments.is_empty() && self.final_offset.is_none()
    }

    pub fn append(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }

        let start = self.end_offset();
        self.bytes.extend(bytes);
        if let Some(last) = self.segments.back_mut() {
            if last.state == SendState::Unsent && last.end_offset() == start {
                last.len += bytes.len();
                return;
            }
        }

        self.segments.push_back(SendSegment {
            offset: start,
            len: bytes.len(),
            state: SendState::Unsent,
        });
    }

    pub fn queue_fin(&mut self) {
        self.final_offset = Some(TrackedFinalOffset {
            offset: self.end_offset(),
            state: SendState::Unsent,
        });
    }

    pub fn next_range(&self, max_payload: usize, peer_max_offset: u64) -> Option<StreamTxRange> {
        let mut unsent = None;
        for segment in &self.segments {
            if !matches!(segment.state, SendState::Lost | SendState::Unsent) {
                continue;
            }

            let credit_remaining = peer_max_offset.saturating_sub(segment.offset);
            let credit_remaining = usize::try_from(credit_remaining).unwrap_or(usize::MAX);
            let len = segment.len.min(max_payload).min(credit_remaining);
            if len == 0 {
                continue;
            }

            let fin = self.final_offset.is_some_and(|final_offset| {
                matches!(final_offset.state, SendState::Lost | SendState::Unsent)
                    && final_offset.offset == segment.offset + len as u64
            });
            let range = StreamTxRange {
                offset: segment.offset,
                len,
                fin,
            };

            if segment.state == SendState::Lost {
                return Some(range);
            }
            if unsent.is_none() {
                unsent = Some(range);
            }
        }

        if let Some(range) = unsent {
            return Some(range);
        }

        let final_offset = self.final_offset.filter(|final_offset| {
            matches!(final_offset.state, SendState::Lost | SendState::Unsent)
                && final_offset.offset <= peer_max_offset
        })?;

        Some(StreamTxRange {
            offset: final_offset.offset,
            len: 0,
            fin: true,
        })
    }

    pub fn ranged_bytes(&self, range: StreamTxRange) -> RangedByteChunks<&VecDeque<u8>> {
        let offset = usize::try_from(range.offset - self.base_offset).unwrap();
        RangedByteChunks {
            inner: &self.bytes,
            offset,
            len: range.len,
        }
    }

    pub fn mark_in_flight(&mut self, range: StreamTxRange) {
        self.set_segment_state(range.offset, range.len, SendState::InFlight);
        if range.fin {
            if let Some(final_offset) = self.final_offset.as_mut() {
                if final_offset.state != SendState::Acked {
                    final_offset.state = SendState::InFlight;
                }
            }
        }
    }

    pub fn mark_lost(&mut self, range: StreamTxRange) {
        self.set_segment_state(range.offset, range.len, SendState::Lost);
        if range.fin {
            if let Some(final_offset) = self.final_offset.as_mut() {
                if final_offset.state != SendState::Acked {
                    final_offset.state = SendState::Lost;
                }
            }
        }
    }

    pub fn mark_acked(&mut self, range: StreamTxRange) {
        self.set_segment_state(range.offset, range.len, SendState::Acked);
        if range.fin {
            if let Some(final_offset) = self.final_offset.as_mut() {
                final_offset.state = SendState::Acked;
            }
        }
        self.trim_acked_prefix();
    }

    pub fn clear(&mut self) {
        self.bytes.clear();
        self.segments.clear();
        self.final_offset = None;
    }

    fn set_segment_state(&mut self, offset: u64, len: usize, state: SendState) {
        if len == 0 {
            return;
        }
        let end = offset + len as u64;

        let Some(index) = self
            .segments
            .iter()
            .position(|segment| segment.offset <= offset && end <= segment.end_offset())
        else {
            return;
        };

        if self.segments[index].state == SendState::Acked && state != SendState::Acked {
            return;
        }

        let segment = self.segments.remove(index).unwrap();
        let mut insert_index = index;

        if segment.offset < offset {
            self.segments.insert(
                insert_index,
                SendSegment {
                    offset: segment.offset,
                    len: usize::try_from(offset - segment.offset).unwrap(),
                    state: segment.state,
                },
            );
            insert_index += 1;
        }

        self.segments
            .insert(insert_index, SendSegment { offset, len, state });
        insert_index += 1;

        if end < segment.end_offset() {
            self.segments.insert(
                insert_index,
                SendSegment {
                    offset: end,
                    len: usize::try_from(segment.end_offset() - end).unwrap(),
                    state: segment.state,
                },
            );
        }

        self.merge_adjacent_segments();
    }

    fn merge_adjacent_segments(&mut self) {
        let mut index = 1;
        while index < self.segments.len() {
            let prev = self.segments[index - 1];
            let next = self.segments[index];
            if prev.state == next.state && prev.end_offset() == next.offset {
                self.segments[index - 1].len += next.len;
                self.segments.remove(index);
            } else {
                index += 1;
            }
        }
    }

    fn trim_acked_prefix(&mut self) {
        while matches!(
            self.segments.front(),
            Some(segment) if segment.state == SendState::Acked
        ) {
            let len = self.segments.pop_front().unwrap().len;
            self.bytes.drain(..len);
            self.base_offset = self.base_offset.saturating_add(len as u64);
        }

        if self.final_offset.is_some_and(|final_offset| {
            final_offset.state == SendState::Acked && final_offset.offset == self.base_offset
        }) {
            self.final_offset = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{StreamTx, StreamTxRange};

    #[test]
    fn append_tracks_unsent_tail() {
        let mut tx = StreamTx::new();
        tx.append(b"abc");
        tx.append(b"de");

        assert_eq!(
            tx.next_range(8, u64::MAX),
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
        tx.append(b"abcdef");

        let first = tx.next_range(3, u64::MAX).unwrap();
        tx.mark_in_flight(first);
        tx.mark_lost(first);

        assert_eq!(
            tx.next_range(3, u64::MAX),
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
        tx.append(b"abcdef");

        let first = tx.next_range(3, u64::MAX).unwrap();
        tx.mark_in_flight(first);
        tx.mark_acked(first);

        assert_eq!(
            tx.next_range(3, u64::MAX),
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

        let range = tx.next_range(16, u64::MAX).unwrap();
        assert_eq!(
            range,
            StreamTxRange {
                offset: 0,
                len: 0,
                fin: true,
            }
        );

        tx.mark_in_flight(range);
        tx.mark_acked(range);
        assert!(tx.is_empty());
    }

    #[test]
    fn subrange_updates_split_merged_in_flight_segments() {
        let mut tx = StreamTx::new();
        tx.append(b"abcdefghijkl");

        let first = tx.next_range(4, u64::MAX).unwrap();
        tx.mark_in_flight(first);
        let second = tx.next_range(4, u64::MAX).unwrap();
        tx.mark_in_flight(second);
        let third = tx.next_range(4, u64::MAX).unwrap();
        tx.mark_in_flight(third);

        tx.mark_lost(StreamTxRange {
            offset: 4,
            len: 4,
            fin: false,
        });

        assert_eq!(
            tx.next_range(4, u64::MAX),
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
        tx.append(b"abcdefghijklmnop");

        let first = tx.next_range(4, u64::MAX).unwrap();
        tx.mark_in_flight(first);
        let second = tx.next_range(4, u64::MAX).unwrap();
        tx.mark_in_flight(second);
        let third = tx.next_range(4, u64::MAX).unwrap();
        tx.mark_in_flight(third);
        let fourth = tx.next_range(4, u64::MAX).unwrap();
        tx.mark_in_flight(fourth);

        tx.mark_acked(StreamTxRange {
            offset: 4,
            len: 4,
            fin: false,
        });
        tx.mark_lost(StreamTxRange {
            offset: 4,
            len: 4,
            fin: false,
        });
        tx.mark_lost(StreamTxRange {
            offset: 8,
            len: 4,
            fin: false,
        });

        assert_eq!(
            tx.next_range(4, u64::MAX),
            Some(StreamTxRange {
                offset: 8,
                len: 4,
                fin: false,
            })
        );
    }
}
