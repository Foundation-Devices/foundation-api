use std::collections::BTreeSet;

use ql_wire::StreamId;

use super::stream_parity::StreamParity;

#[derive(Debug)]
pub struct RemoteStreamHistory {
    parity: StreamParity,
    seen_prefix_end: u32,
    seen_sparse: BTreeSet<u32>,
}

impl RemoteStreamHistory {
    pub fn new(parity: StreamParity) -> Self {
        Self {
            parity,
            seen_prefix_end: 0,
            seen_sparse: BTreeSet::new(),
        }
    }

    /// returns true when this remote stream id was already observed before
    /// panics if stream_id is wrong stream parity
    pub fn observe(&mut self, stream_id: StreamId) -> bool {
        let ordinal = self
            .stream_ordinal(stream_id)
            .expect("remote stream history used with wrong stream parity");
        if ordinal < self.seen_prefix_end {
            return true;
        }
        if ordinal > self.seen_prefix_end {
            return !self.seen_sparse.insert(ordinal);
        }

        self.seen_prefix_end = self.seen_prefix_end.saturating_add(1);
        while self.seen_sparse.remove(&self.seen_prefix_end) {
            self.seen_prefix_end = self.seen_prefix_end.saturating_add(1);
        }
        false
    }

    fn stream_ordinal(&self, stream_id: StreamId) -> Option<u32> {
        let delta = stream_id
            .into_inner()
            .checked_sub(u64::from(self.parity.first_stream_id()))?;
        if delta % 2 != 0 {
            return None;
        }
        u32::try_from(delta / 2).ok()
    }
}
