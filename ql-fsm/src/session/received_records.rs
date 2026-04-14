use std::{ops::RangeInclusive, time::Instant};

use ql_wire::{RecordAck, RecordSeq, WireEncode};

use super::range_set::RangeSet;

#[derive(Debug, Clone)]
pub struct RecordRxState {
    accepted_records: RangeSet,
    pending_ack_ranges: RangeSet,
    ack_state: AckState,
    accepted_record_window: u64,
    pending_ack_range_limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAck {
    pub ack: RecordAck,
    pub due_at: Instant,
    pub includes_all_pending: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveOutcome {
    New,
    Duplicate,
    TooOld,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckState {
    Idle,
    Dirty { due_at: Instant },
}

impl RecordRxState {
    pub fn new(accepted_record_window: u64, pending_ack_range_limit: usize) -> Self {
        Self {
            accepted_records: RangeSet::new(),
            pending_ack_ranges: RangeSet::new(),
            ack_state: AckState::Idle,
            accepted_record_window: accepted_record_window.max(1),
            pending_ack_range_limit: pending_ack_range_limit.max(1),
        }
    }

    pub fn insert(&mut self, seq: RecordSeq) -> ReceiveOutcome {
        let seq = seq.into_inner();
        let largest_accepted = self.accepted_records.max();
        if largest_accepted.is_some_and(|largest| seq < self.accepted_cutoff(largest)) {
            return ReceiveOutcome::TooOld;
        }
        if self.accepted_records.contains(seq) {
            self.pending_ack_ranges.insert(singleton_range(seq));
            self.trim_pending_ack_ranges();
            return ReceiveOutcome::Duplicate;
        }

        self.accepted_records.insert(singleton_range(seq));
        self.trim_accepted_records();

        self.pending_ack_ranges.insert(singleton_range(seq));
        self.trim_pending_ack_ranges();

        ReceiveOutcome::New
    }

    #[cfg(test)]
    pub fn contains(&self, seq: RecordSeq) -> bool {
        self.accepted_records.contains(seq.into_inner())
    }

    #[cfg(test)]
    pub fn largest_accepted(&self) -> Option<RecordSeq> {
        self.accepted_records
            .max()
            .map(|largest| RecordSeq::from_u64(largest).unwrap())
    }

    pub fn ack_deadline(&self) -> Option<Instant> {
        match self.ack_state {
            AckState::Idle => None,
            AckState::Dirty { due_at } => Some(due_at),
        }
    }

    pub fn schedule_ack(&mut self, due_at: Instant) {
        self.ack_state = match self.ack_state {
            AckState::Dirty { due_at: old } => AckState::Dirty {
                due_at: due_at.min(old),
            },
            AckState::Idle => AckState::Dirty { due_at },
        };
    }

    pub fn pending_ack(&self, max_wire_size: usize) -> Option<PendingAck> {
        let due_at = self.ack_deadline()?;
        if max_wire_size == 0 || self.pending_ack_ranges.range_count() == 0 {
            return None;
        }

        let total_range_count = self.pending_ack_ranges.range_count();
        let mut included_range_count = 0usize;
        let mut ranges = Vec::new();
        let mut ack = None;

        for range in self.pending_ack_ranges.iter_rev() {
            ranges.push(to_ack_range(range));
            let candidate = RecordAck::from_ranges(ranges.iter().cloned()).unwrap();
            if candidate.encoded_len() > max_wire_size {
                ranges.pop();
                break;
            }

            included_range_count += 1;
            ack = Some(candidate);
        }

        ack.map(|ack| PendingAck {
            ack,
            due_at,
            includes_all_pending: included_range_count == total_range_count,
        })
    }

    pub fn on_ack_emitted(&mut self, pending_ack: &PendingAck) {
        self.retire_acked_ranges(&pending_ack.ack);
        if pending_ack.includes_all_pending || self.pending_ack_ranges.range_count() == 0 {
            self.ack_state = AckState::Idle;
        }
    }

    pub fn retire_acked_ranges(&mut self, ack: &RecordAck) {
        for range in ack.ranges() {
            self.pending_ack_ranges.remove(from_ack_range(range));
        }
        if self.pending_ack_ranges.range_count() == 0 {
            self.ack_state = AckState::Idle;
        }
    }

    pub fn clear_ack_state(&mut self) {
        self.ack_state = AckState::Idle;
    }

    pub fn restore_acked_ranges(&mut self, ack: &RecordAck, due_at: Instant) {
        for range in ack.ranges() {
            self.pending_ack_ranges.insert(from_ack_range(range));
        }
        self.trim_pending_ack_ranges();
        self.schedule_ack(due_at);
    }

    fn accepted_cutoff(&self, largest_accepted: u64) -> u64 {
        largest_accepted
            .saturating_add(1)
            .saturating_sub(self.accepted_record_window)
    }

    fn trim_accepted_records(&mut self) {
        let Some(largest_accepted) = self.accepted_records.max() else {
            return;
        };
        let cutoff = self.accepted_cutoff(largest_accepted);
        self.accepted_records.remove(0..cutoff);
    }

    fn trim_pending_ack_ranges(&mut self) {
        while self.pending_ack_ranges.range_count() > self.pending_ack_range_limit {
            self.pending_ack_ranges.pop_min();
        }
    }
}

fn singleton_range(seq: u64) -> std::ops::Range<u64> {
    seq..seq.checked_add(1).unwrap()
}

fn to_ack_range(range: std::ops::Range<u64>) -> RangeInclusive<RecordSeq> {
    let end = range.end.checked_sub(1).unwrap();
    RecordSeq::from_u64(range.start).unwrap()..=RecordSeq::from_u64(end).unwrap()
}

fn from_ack_range(range: RangeInclusive<RecordSeq>) -> std::ops::Range<u64> {
    let start = range.start().into_inner();
    let end = range.end().into_inner().checked_add(1).unwrap();
    start..end
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use ql_wire::RecordSeq;

    use super::{PendingAck, ReceiveOutcome, RecordRxState};

    fn seq(value: u64) -> RecordSeq {
        RecordSeq::from_u64(value).unwrap()
    }

    fn ack_ranges(pending_ack: PendingAck) -> Vec<(u64, u64)> {
        pending_ack
            .ack
            .ranges()
            .map(|range| (range.start().into_inner(), range.end().into_inner()))
            .collect()
    }

    #[test]
    fn contiguous_records_emit_one_ack_range() {
        let now = Instant::now();
        let mut record_rx = RecordRxState::new(128, 8);

        assert_eq!(record_rx.insert(seq(10)), ReceiveOutcome::New);
        assert_eq!(record_rx.insert(seq(11)), ReceiveOutcome::New);
        assert_eq!(record_rx.insert(seq(12)), ReceiveOutcome::New);

        record_rx.schedule_ack(now);
        let pending_ack = record_rx.pending_ack(usize::MAX).unwrap();
        assert_eq!(ack_ranges(pending_ack), vec![(10, 12)]);
    }

    #[test]
    fn sparse_records_emit_descending_ack_ranges() {
        let now = Instant::now();
        let mut record_rx = RecordRxState::new(128, 8);

        assert_eq!(record_rx.insert(seq(10)), ReceiveOutcome::New);
        assert_eq!(record_rx.insert(seq(15)), ReceiveOutcome::New);
        assert_eq!(record_rx.insert(seq(16)), ReceiveOutcome::New);
        assert_eq!(record_rx.insert(seq(12)), ReceiveOutcome::New);

        record_rx.schedule_ack(now + Duration::from_millis(5));
        let pending_ack = record_rx.pending_ack(usize::MAX).unwrap();
        assert_eq!(ack_ranges(pending_ack), vec![(15, 16), (12, 12), (10, 10)]);
    }

    #[test]
    fn accepted_record_window_evicts_old_sequences() {
        let mut record_rx = RecordRxState::new(4, 8);

        assert_eq!(record_rx.insert(seq(10)), ReceiveOutcome::New);
        assert_eq!(record_rx.insert(seq(15)), ReceiveOutcome::New);

        assert_eq!(record_rx.insert(seq(10)), ReceiveOutcome::TooOld);
        assert!(!record_rx.contains(seq(10)));
        assert_eq!(record_rx.largest_accepted(), Some(seq(15)));
    }

    #[test]
    fn pending_ack_range_limit_drops_oldest_low_ranges() {
        let now = Instant::now();
        let mut record_rx = RecordRxState::new(128, 2);

        assert_eq!(record_rx.insert(seq(1)), ReceiveOutcome::New);
        assert_eq!(record_rx.insert(seq(3)), ReceiveOutcome::New);
        assert_eq!(record_rx.insert(seq(5)), ReceiveOutcome::New);

        record_rx.schedule_ack(now);
        let pending_ack = record_rx.pending_ack(usize::MAX).unwrap();
        assert_eq!(ack_ranges(pending_ack), vec![(5, 5), (3, 3)]);
    }

    #[test]
    fn retire_acked_ranges_removes_only_exact_snapshot() {
        let now = Instant::now();
        let mut record_rx = RecordRxState::new(128, 8);

        assert_eq!(record_rx.insert(seq(1)), ReceiveOutcome::New);
        assert_eq!(record_rx.insert(seq(3)), ReceiveOutcome::New);
        assert_eq!(record_rx.insert(seq(5)), ReceiveOutcome::New);
        record_rx.schedule_ack(now);

        let first_ack = record_rx.pending_ack(4).unwrap();
        assert_eq!(ack_ranges(first_ack.clone()), vec![(5, 5)]);
        record_rx.on_ack_emitted(&first_ack);
        record_rx.retire_acked_ranges(&first_ack.ack);

        let second_ack = record_rx.pending_ack(usize::MAX).unwrap();
        assert_eq!(ack_ranges(second_ack), vec![(3, 3), (1, 1)]);
    }
}
