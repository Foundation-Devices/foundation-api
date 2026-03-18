use std::array;

use crate::wire::StreamSeq;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqRingInsertError {
    OutOfWindow,
    Occupied,
}

#[derive(Debug)]
pub struct SeqRing<const N: usize, T> {
    base_seq: StreamSeq,
    head: usize,
    len: usize,
    slots: [Option<T>; N],
}

impl<const N: usize, T> SeqRing<N, T> {
    pub fn new(base_seq: StreamSeq) -> Self {
        Self {
            base_seq,
            head: 0,
            len: 0,
            slots: array::from_fn(|_| None),
        }
    }

    pub fn base_seq(&self) -> StreamSeq {
        self.base_seq
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear_with_base(&mut self, base_seq: StreamSeq) {
        for slot in &mut self.slots {
            let _ = slot.take();
        }
        self.base_seq = base_seq;
        self.head = 0;
        self.len = 0;
    }

    pub fn contains_key(&self, seq: &StreamSeq) -> bool {
        self.get(seq).is_some()
    }

    pub fn accepts_seq(&self, seq: StreamSeq) -> bool {
        self.offset_for(seq).is_some()
    }

    pub fn get(&self, seq: &StreamSeq) -> Option<&T> {
        let index = self.index_for(*seq)?;
        self.slots[index].as_ref()
    }

    pub fn get_mut(&mut self, seq: &StreamSeq) -> Option<&mut T> {
        let index = self.index_for(*seq)?;
        self.slots[index].as_mut()
    }

    pub fn insert(&mut self, seq: StreamSeq, value: T) -> Result<(), SeqRingInsertError> {
        let index = self.index_for(seq).ok_or(SeqRingInsertError::OutOfWindow)?;
        if self.slots[index].is_some() {
            return Err(SeqRingInsertError::Occupied);
        }
        self.slots[index] = Some(value);
        self.len += 1;
        Ok(())
    }

    pub fn set(&mut self, seq: StreamSeq, value: T) -> Result<Option<T>, SeqRingInsertError> {
        let index = self.index_for(seq).ok_or(SeqRingInsertError::OutOfWindow)?;
        let previous = self.slots[index].replace(value);
        if previous.is_none() {
            self.len += 1;
        }
        Ok(previous)
    }

    pub fn remove(&mut self, seq: &StreamSeq) -> Option<T> {
        let index = self.index_for(*seq)?;
        let value = self.slots[index].take();
        if value.is_some() {
            self.len -= 1;
        }
        value
    }

    pub fn take_front(&mut self) -> Option<(StreamSeq, T)> {
        let value = self.slots[self.head].take()?;
        let seq = self.base_seq;
        self.len -= 1;
        self.head = self.next_index(self.head);
        self.base_seq = self.base_seq.next();
        Some((seq, value))
    }

    pub fn advance_empty_front_until(&mut self, limit_seq: StreamSeq) {
        while self.base_seq.serial_lt(limit_seq) && self.slots[self.head].is_none() {
            self.head = self.next_index(self.head);
            self.base_seq = self.base_seq.next();
        }
    }

    pub fn drain_front(&mut self) -> SeqRingDrain<'_, N, T> {
        SeqRingDrain { ring: self }
    }

    pub fn iter(&self) -> SeqRingIter<'_, N, T> {
        SeqRingIter {
            ring: self,
            offset: 0,
        }
    }

    pub fn bitmap(&self) -> u8 {
        debug_assert!(N <= 8);
        let mut bitmap = 0u8;
        for offset in 0..N {
            let index = self.index_for_offset(offset);
            if self.slots[index].is_some() {
                bitmap |= 1u8 << offset;
            }
        }
        bitmap
    }

    fn index_for(&self, seq: StreamSeq) -> Option<usize> {
        let offset = self.offset_for(seq)?;
        Some(self.index_for_offset(offset))
    }

    fn offset_for(&self, seq: StreamSeq) -> Option<usize> {
        let offset = self.base_seq.forward_distance_to(seq)? as usize;
        (offset < N).then_some(offset)
    }

    fn index_for_offset(&self, offset: usize) -> usize {
        (self.head + offset) % N
    }

    fn next_index(&self, index: usize) -> usize {
        (index + 1) % N
    }
}

pub struct SeqRingIter<'a, const N: usize, T> {
    ring: &'a SeqRing<N, T>,
    offset: usize,
}

impl<'a, const N: usize, T> Iterator for SeqRingIter<'a, N, T> {
    type Item = (StreamSeq, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        while self.offset < N {
            let offset = self.offset;
            self.offset += 1;
            let index = self.ring.index_for_offset(offset);
            if let Some(value) = self.ring.slots[index].as_ref() {
                let seq = self.ring.base_seq.add(offset as u32);
                return Some((seq, value));
            }
        }
        None
    }
}

pub struct SeqRingDrain<'a, const N: usize, T> {
    ring: &'a mut SeqRing<N, T>,
}

impl<'a, const N: usize, T> Iterator for SeqRingDrain<'a, N, T> {
    type Item = (StreamSeq, T);

    fn next(&mut self) -> Option<Self::Item> {
        self.ring.take_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        engine::stream::{BufferIncomingResult, InFlightFrame, StreamControl},
        wire::stream::{
            BodyChunk, Direction, StreamAck, StreamFrame, StreamFrameData, StreamFrameOpen,
        },
        StreamId,
    };

    fn data_frame(stream_id: StreamId, tx_seq: u32, byte: u8) -> (StreamSeq, StreamFrame) {
        (
            StreamSeq(tx_seq),
            StreamFrame::Data(StreamFrameData {
                stream_id,
                dir: Direction::Request,
                chunk: BodyChunk {
                    bytes: vec![byte],
                    fin: false,
                },
            }),
        )
    }

    #[test]
    fn seq_ring_drain_front_takes_contiguous_items_in_order() {
        let mut ring = SeqRing::<8, u64>::new(StreamSeq(1));
        ring.insert(StreamSeq(2), 20).unwrap();
        ring.insert(StreamSeq(1), 10).unwrap();
        ring.insert(StreamSeq(3), 30).unwrap();

        let drained: Vec<_> = ring.drain_front().collect();
        assert_eq!(
            drained,
            vec![(StreamSeq(1), 10), (StreamSeq(2), 20), (StreamSeq(3), 30)]
        );
        assert_eq!(ring.base_seq(), StreamSeq(4));
        assert!(ring.is_empty());
    }

    #[test]
    fn seq_ring_wraps_and_reuses_slots() {
        let mut ring = SeqRing::<4, u64>::new(StreamSeq(1));
        ring.insert(StreamSeq(1), 1).unwrap();
        ring.insert(StreamSeq(2), 2).unwrap();
        ring.insert(StreamSeq(3), 3).unwrap();

        assert_eq!(ring.take_front(), Some((StreamSeq(1), 1)));
        assert_eq!(ring.take_front(), Some((StreamSeq(2), 2)));

        ring.insert(StreamSeq(4), 4).unwrap();
        ring.insert(StreamSeq(5), 5).unwrap();

        let remaining: Vec<_> = ring.iter().map(|(seq, value)| (seq, *value)).collect();
        assert_eq!(
            remaining,
            vec![(StreamSeq(3), 3), (StreamSeq(4), 4), (StreamSeq(5), 5)]
        );
    }

    #[test]
    fn seq_ring_selective_take_can_slide_past_empty_front() {
        let mut ring = SeqRing::<8, u64>::new(StreamSeq(1));
        for value in 1..=4 {
            ring.insert(StreamSeq(value), value as u64).unwrap();
        }

        assert_eq!(ring.remove(&StreamSeq(2)), Some(2));
        assert_eq!(ring.remove(&StreamSeq(3)), Some(3));
        ring.advance_empty_front_until(StreamSeq(5));
        assert_eq!(ring.base_seq(), StreamSeq(1));

        assert_eq!(ring.remove(&StreamSeq(1)), Some(1));
        ring.advance_empty_front_until(StreamSeq(5));
        assert_eq!(ring.base_seq(), StreamSeq(4));

        assert_eq!(ring.remove(&StreamSeq(4)), Some(4));
        ring.advance_empty_front_until(StreamSeq(5));
        assert_eq!(ring.base_seq(), StreamSeq(5));
        assert!(ring.is_empty());
    }

    #[test]
    fn stream_control_recv_buffer_preserves_ack_bitmap_and_drain_order() {
        let stream_id = StreamId(7);
        let mut control = StreamControl::default();

        let (seq2, frame2) = data_frame(stream_id, 2, b'b');
        let (seq1, frame1) = data_frame(stream_id, 1, b'a');
        let (seq3, frame3) = data_frame(stream_id, 3, b'c');

        assert!(matches!(
            control.buffer_incoming(seq2, frame2),
            BufferIncomingResult::Buffered { out_of_order: true }
        ));
        assert_eq!(control.current_ack().base, StreamSeq(0));
        assert_eq!(control.current_ack().bitmap, 0b0000_0010);

        assert!(matches!(
            control.buffer_incoming(seq1, frame1),
            BufferIncomingResult::Buffered {
                out_of_order: false
            }
        ));
        assert!(matches!(
            control.buffer_incoming(seq3, frame3),
            BufferIncomingResult::Buffered { out_of_order: true }
        ));

        let committed: Vec<_> = std::iter::from_fn(|| control.pop_next_committable()).collect();
        assert_eq!(
            committed.iter().map(|(seq, _)| *seq).collect::<Vec<_>>(),
            vec![StreamSeq(1), StreamSeq(2), StreamSeq(3)]
        );
        assert_eq!(control.committed_rx_seq(), StreamSeq(3));
        assert_eq!(control.current_ack().base, StreamSeq(3));
        assert_eq!(control.current_ack().bitmap, 0);
    }

    #[test]
    fn stream_control_send_window_respects_sequence_range_not_count() {
        let stream_id = StreamId(11);
        let mut control = StreamControl::default();
        for tx_seq in 1..=8 {
            let frame = InFlightFrame {
                tx_seq: StreamSeq(tx_seq),
                frame: StreamFrame::Open(StreamFrameOpen {
                    stream_id,
                    request_head: vec![tx_seq as u8],
                    request_prefix: None,
                }),
                attempt: 0,
            };
            control.insert_in_flight(frame);
            control.next_tx_seq = StreamSeq(tx_seq + 1);
        }

        assert!(!control.send_window_has_space());
        let _ = control.remove_in_flight(StreamSeq(8));
        assert!(!control.send_window_has_space());
        let _ = control.remove_in_flight(StreamSeq(1));
        assert!(control.send_window_has_space());
        assert_eq!(control.in_flight.base_seq(), StreamSeq(2));
    }

    #[test]
    fn ack_coverage_handles_wraparound_bitmap() {
        let ack = StreamAck {
            base: StreamSeq(u32::MAX),
            bitmap: 0b0000_0011,
        };

        assert!(StreamControl::ack_covers(ack, StreamSeq(u32::MAX - 1)));
        assert!(StreamControl::ack_covers(ack, StreamSeq(u32::MAX)));
        assert!(StreamControl::ack_covers(ack, StreamSeq(0)));
        assert!(StreamControl::ack_covers(ack, StreamSeq(1)));
        assert!(!StreamControl::ack_covers(ack, StreamSeq(2)));
    }

    #[test]
    fn seq_ring_accepts_window_across_sequence_overflow() {
        let mut ring = SeqRing::<4, u64>::new(StreamSeq(u32::MAX - 1));
        ring.insert(StreamSeq(u32::MAX - 1), 1).unwrap();
        ring.insert(StreamSeq(u32::MAX), 2).unwrap();
        ring.insert(StreamSeq(0), 3).unwrap();

        assert_eq!(ring.take_front(), Some((StreamSeq(u32::MAX - 1), 1)));
        assert_eq!(ring.take_front(), Some((StreamSeq(u32::MAX), 2)));

        ring.insert(StreamSeq(1), 4).unwrap();
        ring.insert(StreamSeq(2), 5).unwrap();

        let remaining: Vec<_> = ring.iter().map(|(seq, value)| (seq, *value)).collect();
        assert_eq!(
            remaining,
            vec![(StreamSeq(0), 3), (StreamSeq(1), 4), (StreamSeq(2), 5)]
        );
    }

    #[test]
    fn seq_ring_selective_take_slides_across_sequence_overflow() {
        let mut ring = SeqRing::<8, u64>::new(StreamSeq(u32::MAX - 1));
        for (seq, value) in [
            (StreamSeq(u32::MAX - 1), 1u64),
            (StreamSeq(u32::MAX), 2u64),
            (StreamSeq(0), 3u64),
            (StreamSeq(1), 4u64),
        ] {
            ring.insert(seq, value).unwrap();
        }

        assert_eq!(ring.remove(&StreamSeq(u32::MAX)), Some(2));
        assert_eq!(ring.remove(&StreamSeq(0)), Some(3));
        ring.advance_empty_front_until(StreamSeq(2));
        assert_eq!(ring.base_seq(), StreamSeq(u32::MAX - 1));

        assert_eq!(ring.remove(&StreamSeq(u32::MAX - 1)), Some(1));
        ring.advance_empty_front_until(StreamSeq(2));
        assert_eq!(ring.base_seq(), StreamSeq(1));

        assert_eq!(ring.remove(&StreamSeq(1)), Some(4));
        ring.advance_empty_front_until(StreamSeq(2));
        assert_eq!(ring.base_seq(), StreamSeq(2));
        assert!(ring.is_empty());
    }
}
