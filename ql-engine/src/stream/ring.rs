use std::array;

use crate::wire::StreamSeq;

#[derive(Debug)]
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
                return Some((self.ring.base_seq.add(offset as u32), value));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
