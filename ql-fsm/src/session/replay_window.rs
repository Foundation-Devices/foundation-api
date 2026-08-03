use ql_wire::RecordSeq;

use super::range_set::{single_range, RangeSet};

#[derive(Debug, Clone)]
pub struct ReplayWindow {
    accepted: RangeSet,
    window: u64,
}

impl ReplayWindow {
    pub fn new(window: u64) -> Self {
        Self {
            accepted: RangeSet::new(),
            window: window.max(1),
        }
    }

    /// returns true when `seq` was already accepted or has aged out of the window
    pub fn is_replay(&self, seq: RecordSeq) -> bool {
        let Some(cutoff) = self.cutoff() else {
            return false;
        };
        seq.0 < cutoff || self.accepted.contains(seq.0)
    }

    /// records `seq` as accepted
    ///
    /// callers must reject replays with `is_replay` first
    pub fn accept(&mut self, seq: RecordSeq) {
        debug_assert!(!self.is_replay(seq), "accepting a replayed seq");
        self.accepted.insert(single_range(seq.0));
        self.trim();
    }

    fn cutoff(&self) -> Option<u64> {
        Some(self.accepted.max()?.saturating_sub(self.window - 1))
    }

    fn trim(&mut self) {
        if let Some(cutoff) = self.cutoff() {
            self.accepted.remove(0..cutoff);
        }
    }
}

#[cfg(test)]
mod tests {
    use ql_wire::RecordSeq;

    use super::ReplayWindow;

    #[test]
    fn window_evicts_old_sequences() {
        let mut window = ReplayWindow::new(4);

        window.accept(RecordSeq(10));
        window.accept(RecordSeq(15));

        assert!(window.is_replay(RecordSeq(10)));
    }
}
