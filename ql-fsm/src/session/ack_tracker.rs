use std::{ops::RangeInclusive, time::Instant};

use ql_wire::{RecordAck, RecordAckBuilder, RecordSeq};

use super::range_set::{single_range, RangeSet};

#[derive(Debug, Clone)]
pub struct AckTracker {
    pending_ack: RangeSet,
    ack_due_at: Option<Instant>,
    pending_ack_range_limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAck {
    pub ack: RecordAck,
    pub due_at: Instant,
    pub includes_all_pending: bool,
}

impl AckTracker {
    pub fn new(pending_ack_range_limit: usize) -> Self {
        Self {
            pending_ack: RangeSet::new(),
            ack_due_at: None,
            pending_ack_range_limit: pending_ack_range_limit.max(1),
        }
    }

    /// queues an ack for `seq`
    pub fn push(&mut self, seq: RecordSeq) {
        self.pending_ack.insert(single_range(seq.0));
        self.trim_pending_ack_ranges();
    }

    pub fn ack_deadline(&self) -> Option<Instant> {
        self.ack_due_at
    }

    pub fn schedule_ack(&mut self, due_at: Instant) {
        self.ack_due_at = Some(self.ack_due_at.map_or(due_at, |old| old.min(due_at)));
    }

    pub fn pending_ack(&self, max_wire_size: usize) -> Option<PendingAck> {
        let due_at = self.ack_deadline()?;
        let total_range_count = self.pending_ack.range_count();
        if max_wire_size == 0 || total_range_count == 0 {
            return None;
        }

        let mut ack = RecordAckBuilder::new();
        let mut selected_range_count = 0usize;

        for range in self.pending_ack.iter_rev() {
            let pushed = ack
                .try_push_range(to_ack_range(range), max_wire_size)
                .unwrap();
            if !pushed {
                break;
            }
            selected_range_count += 1;
        }

        (selected_range_count != 0).then(|| PendingAck {
            ack: ack.build().unwrap(),
            due_at,
            includes_all_pending: total_range_count == selected_range_count,
        })
    }

    pub fn on_ack_emitted(&mut self, pending_ack: &PendingAck) {
        for range in pending_ack.ack.ranges() {
            self.pending_ack.remove(from_ack_range(range));
        }
        if pending_ack.includes_all_pending || self.pending_ack.range_count() == 0 {
            self.ack_due_at = None;
        }
    }

    pub fn restore_acked_ranges(&mut self, ack: &RecordAck, due_at: Instant) {
        for range in ack.ranges() {
            self.pending_ack.insert(from_ack_range(range));
        }
        self.trim_pending_ack_ranges();
        self.schedule_ack(due_at);
    }

    fn trim_pending_ack_ranges(&mut self) {
        while self.pending_ack.range_count() > self.pending_ack_range_limit {
            self.pending_ack.pop_min();
        }
    }
}

fn to_ack_range(range: std::ops::Range<u64>) -> RangeInclusive<RecordSeq> {
    let end = range.end.checked_sub(1).unwrap();
    RecordSeq(range.start)..=RecordSeq(end)
}

fn from_ack_range(range: RangeInclusive<RecordSeq>) -> std::ops::Range<u64> {
    let start = range.start().0;
    let end = range.end().0.checked_add(1).unwrap();
    start..end
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use ql_wire::RecordSeq;

    use super::{AckTracker, PendingAck};

    fn ack_ranges(pending_ack: &PendingAck) -> Vec<(u64, u64)> {
        pending_ack
            .ack
            .ranges()
            .map(|range| (range.start().0, range.end().0))
            .collect()
    }

    #[test]
    fn contiguous_records_emit_one_ack_range() {
        let now = Instant::now();
        let mut ack_tracker = AckTracker::new(8);

        ack_tracker.push(RecordSeq(10));
        ack_tracker.push(RecordSeq(11));
        ack_tracker.push(RecordSeq(12));

        ack_tracker.schedule_ack(now);
        let pending_ack = ack_tracker.pending_ack(usize::MAX).unwrap();
        assert_eq!(ack_ranges(&pending_ack), vec![(10, 12)]);
    }

    #[test]
    fn sparse_records_emit_descending_ack_ranges() {
        let now = Instant::now();
        let mut ack_tracker = AckTracker::new(8);

        ack_tracker.push(RecordSeq(10));
        ack_tracker.push(RecordSeq(15));
        ack_tracker.push(RecordSeq(16));
        ack_tracker.push(RecordSeq(12));

        ack_tracker.schedule_ack(now + Duration::from_millis(5));
        let pending_ack = ack_tracker.pending_ack(usize::MAX).unwrap();
        assert_eq!(ack_ranges(&pending_ack), vec![(15, 16), (12, 12), (10, 10)]);
    }

    #[test]
    fn pending_ack_range_limit_drops_oldest_low_ranges() {
        let now = Instant::now();
        let mut ack_tracker = AckTracker::new(2);

        ack_tracker.push(RecordSeq(1));
        ack_tracker.push(RecordSeq(3));
        ack_tracker.push(RecordSeq(5));

        ack_tracker.schedule_ack(now);
        let pending_ack = ack_tracker.pending_ack(usize::MAX).unwrap();
        assert_eq!(ack_ranges(&pending_ack), vec![(5, 5), (3, 3)]);
    }

    #[test]
    fn emitting_an_ack_retires_only_its_own_ranges() {
        let now = Instant::now();
        let mut ack_tracker = AckTracker::new(8);

        ack_tracker.push(RecordSeq(1));
        ack_tracker.push(RecordSeq(3));
        ack_tracker.push(RecordSeq(5));
        ack_tracker.schedule_ack(now);

        let first_ack = ack_tracker.pending_ack(4).unwrap();
        assert_eq!(ack_ranges(&first_ack), vec![(5, 5)]);
        ack_tracker.on_ack_emitted(&first_ack);

        let second_ack = ack_tracker.pending_ack(usize::MAX).unwrap();
        assert_eq!(ack_ranges(&second_ack), vec![(3, 3), (1, 1)]);
    }
}
