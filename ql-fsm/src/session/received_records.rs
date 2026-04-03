use std::collections::BTreeSet;

use ql_wire::{RecordAck, RecordAckRange, RecordSeq};

#[derive(Debug, Default)]
pub struct ReceivedRecords {
    seen: BTreeSet<u64>,
    largest: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveInsertOutcome {
    New { out_of_order: bool },
    Duplicate,
}

impl ReceivedRecords {
    const TRACKED_WINDOW: u64 = 256;

    pub fn insert(&mut self, seq: RecordSeq) -> ReceiveInsertOutcome {
        if self.seen.contains(&seq.0) {
            return ReceiveInsertOutcome::Duplicate;
        }

        if self
            .largest
            .is_some_and(|largest| largest.saturating_sub(seq.0) > Self::TRACKED_WINDOW)
        {
            return ReceiveInsertOutcome::Duplicate;
        }

        let out_of_order = self
            .largest
            .is_some_and(|largest| seq.0 != largest.saturating_add(1));
        self.seen.insert(seq.0);
        self.largest = Some(self.largest.map_or(seq.0, |largest| largest.max(seq.0)));
        self.prune();
        ReceiveInsertOutcome::New { out_of_order }
    }

    pub fn ack(&self) -> Option<RecordAck> {
        if self.seen.is_empty() {
            return None;
        }

        let mut ranges = Vec::new();
        let mut iter = self.seen.iter().copied();
        let first = iter.next()?;
        let mut start = first;
        let mut end = first.saturating_add(1);

        for seq in iter {
            if seq == end {
                end = end.saturating_add(1);
                continue;
            }

            ranges.push(RecordAckRange { start, end });
            start = seq;
            end = seq.saturating_add(1);
        }

        ranges.push(RecordAckRange { start, end });
        Some(RecordAck { ranges })
    }

    fn prune(&mut self) {
        let Some(largest) = self.largest else {
            return;
        };
        let keep_from = largest.saturating_sub(Self::TRACKED_WINDOW);
        self.seen.retain(|seq| *seq >= keep_from);
    }
}
