use std::array;

use ql_wire::SessionSeq;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqRingInsertError {
    OutOfWindow,
    Occupied,
}

#[derive(Debug)]
pub struct SeqRing<const N: usize, T> {
    base_seq: SessionSeq,
    head: usize,
    len: usize,
    slots: [Option<T>; N],
}

impl<const N: usize, T> SeqRing<N, T> {
    pub fn new(base_seq: SessionSeq) -> Self {
        Self {
            base_seq,
            head: 0,
            len: 0,
            slots: array::from_fn(|_| None),
        }
    }

    pub fn base_seq(&self) -> SessionSeq {
        self.base_seq
    }

    pub fn accepts_seq(&self, seq: SessionSeq) -> bool {
        self.offset_for(seq).is_some()
    }

    pub fn contains_key(&self, seq: &SessionSeq) -> bool {
        self.get(seq).is_some()
    }

    pub fn get(&self, seq: &SessionSeq) -> Option<&T> {
        let index = self.index_for(*seq)?;
        self.slots[index].as_ref()
    }

    pub fn insert(&mut self, seq: SessionSeq, value: T) -> Result<(), SeqRingInsertError> {
        let index = self.index_for(seq).ok_or(SeqRingInsertError::OutOfWindow)?;
        if self.slots[index].is_some() {
            return Err(SeqRingInsertError::Occupied);
        }
        self.slots[index] = Some(value);
        self.len += 1;
        Ok(())
    }

    pub fn remove(&mut self, seq: &SessionSeq) -> Option<T> {
        let index = self.index_for(*seq)?;
        let value = self.slots[index].take();
        if value.is_some() {
            self.len -= 1;
        }
        value
    }

    pub fn advance_empty_front_until(&mut self, limit_seq: SessionSeq) {
        while self.base_seq.0 < limit_seq.0 && self.slots[self.head].is_none() {
            self.head = self.next_index(self.head);
            self.base_seq = SessionSeq(self.base_seq.0 + 1);
        }
    }

    pub fn advance_occupied_front(&mut self) {
        while self.slots[self.head].is_some() {
            let _ = self.slots[self.head].take();
            self.len -= 1;
            self.head = self.next_index(self.head);
            self.base_seq = SessionSeq(self.base_seq.0 + 1);
        }
    }

    pub fn iter(&self) -> SeqRingIter<'_, N, T> {
        SeqRingIter {
            ring: self,
            offset: 0,
        }
    }

    pub fn bitmap(&self) -> u64 {
        debug_assert!(N <= 64);
        let mut bitmap = 0u64;
        for offset in 0..N {
            let index = self.index_for_offset(offset);
            if self.slots[index].is_some() {
                bitmap |= 1u64 << offset;
            }
        }
        bitmap
    }

    fn index_for(&self, seq: SessionSeq) -> Option<usize> {
        let offset = self.offset_for(seq)?;
        Some(self.index_for_offset(offset))
    }

    fn offset_for(&self, seq: SessionSeq) -> Option<usize> {
        if seq.0 < self.base_seq.0 {
            return None;
        }
        let offset = (seq.0 - self.base_seq.0) as usize;
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
    type Item = (SessionSeq, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        while self.offset < N {
            let offset = self.offset;
            self.offset += 1;
            let index = self.ring.index_for_offset(offset);
            if let Some(value) = self.ring.slots[index].as_ref() {
                return Some((SessionSeq(self.ring.base_seq.0 + offset as u64), value));
            }
        }
        None
    }
}
