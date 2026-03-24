use std::array;

pub const STREAM_RECV_WINDOW_CAPACITY: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RxChunk {
    pub bytes: Vec<u8>,
    pub fin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvInsertOutcome {
    Inserted,
    Duplicate,
    RejectNoAck,
    Conflict,
}

#[derive(Debug)]
pub struct StreamRecvWindow {
    next_chunk_seq: u64,
    slots: [Option<RxChunk>; STREAM_RECV_WINDOW_CAPACITY],
}

impl StreamRecvWindow {
    pub fn new() -> Self {
        Self {
            next_chunk_seq: 0,
            slots: array::from_fn(|_| None),
        }
    }

    pub fn clear(&mut self) {
        self.slots.fill(None);
    }

    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }

    pub fn next_chunk_seq(&self) -> u64 {
        self.next_chunk_seq
    }

    pub fn insert(&mut self, chunk_seq: u64, chunk: RxChunk) -> RecvInsertOutcome {
        let Some(delta) = chunk_seq.checked_sub(self.next_chunk_seq) else {
            return RecvInsertOutcome::Duplicate;
        };
        if delta >= self.slots.len() as u64 {
            return RecvInsertOutcome::RejectNoAck;
        }

        let slot = &mut self.slots[delta as usize];
        match slot {
            Some(existing) if *existing == chunk => RecvInsertOutcome::Duplicate,
            Some(_) => RecvInsertOutcome::Conflict,
            None => {
                *slot = Some(chunk);
                RecvInsertOutcome::Inserted
            }
        }
    }

    pub fn pop_contiguous(&mut self) -> Option<RxChunk> {
        let chunk = self.slots[0].take()?;
        self.next_chunk_seq += 1;
        self.slots.rotate_left(1);
        self.slots[self.slots.len() - 1] = None;
        Some(chunk)
    }
}
