use ql_wire::StreamId;

use super::{range_set::RangeSet, stream_parity::StreamParity};

#[derive(Debug)]
pub struct RemoteStreamHistory {
    parity: StreamParity,
    seen: RangeSet,
}

impl RemoteStreamHistory {
    pub fn new(parity: StreamParity) -> Self {
        Self {
            parity,
            seen: RangeSet::new(),
        }
    }

    /// returns true when this remote stream id was already observed before
    /// panics if stream_id is wrong stream parity
    pub fn observe(&mut self, stream_id: StreamId) -> bool {
        let ordinal = self
            .stream_ordinal(stream_id)
            .expect("remote stream history used with wrong stream parity");
        !self.seen.insert(ordinal..ordinal + 1)
    }

    fn stream_ordinal(&self, stream_id: StreamId) -> Option<u64> {
        let delta = stream_id
            .into_inner()
            .checked_sub(u64::from(self.parity.first_stream_id()))?;
        if delta % 2 != 0 {
            return None;
        }
        Some(delta / 2)
    }
}

#[cfg(test)]
mod tests {
    use super::RemoteStreamHistory;
    use crate::session::stream_parity::StreamParity;

    #[test]
    fn observe() {
        let parity = StreamParity::Even;
        let mut history = RemoteStreamHistory::new(parity);

        assert!(!history.observe(parity.make_stream_id(2)));
        assert!(!history.observe(parity.make_stream_id(5)));
        assert!(!history.observe(parity.make_stream_id(0)));
        assert!(!history.observe(parity.make_stream_id(4)));
        assert!(history.observe(parity.make_stream_id(2)));
        assert!(!history.observe(parity.make_stream_id(1)));
        assert!(history.observe(parity.make_stream_id(5)));
        assert!(!history.observe(parity.make_stream_id(3)));
        assert!(history.observe(parity.make_stream_id(0)));
    }
}
