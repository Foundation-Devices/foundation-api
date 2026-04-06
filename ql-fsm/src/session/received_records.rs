use ql_wire::{RecordAck, RecordSeq};

#[derive(Debug, Clone, Default)]
pub struct ReceivedRecords {
    seen: u64,
    base: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveOutcome {
    New { out_of_order: bool },
    Duplicate,
    TooOld,
}

impl ReceivedRecords {
    const TRACKED_LEN: u64 = RecordAck::BITMAP_BITS as u64;
    const TRACKED_WINDOW: u64 = Self::TRACKED_LEN - 1;

    pub fn insert(&mut self, seq: RecordSeq) -> ReceiveOutcome {
        let seq = seq.into_inner();
        if self.seen == 0 {
            self.base = seq;
            self.seen = 1;
            return ReceiveOutcome::New {
                out_of_order: false,
            };
        }

        if seq < self.base {
            return ReceiveOutcome::TooOld;
        }

        let base = self.base.max(seq.saturating_sub(Self::TRACKED_WINDOW));
        let seen = self.rebased_seen(base);
        let next_seen = seen | (1u64 << (seq - base));
        if next_seen == seen {
            return ReceiveOutcome::Duplicate;
        }

        let out_of_order = seq
            != self
                .base
                .saturating_add(u64::from(u64::BITS - 1 - self.seen.leading_zeros()))
                .saturating_add(1);
        self.base = base;
        self.seen = next_seen;
        ReceiveOutcome::New { out_of_order }
    }

    pub fn ack(&self) -> Option<RecordAck> {
        (self.seen != 0).then_some(RecordAck {
            base_seq: RecordSeq::from_u64(self.base).expect("tracked record seq must fit varint"),
            bits: self.seen,
        })
    }

    fn rebased_seen(&self, new_base: u64) -> u64 {
        if new_base <= self.base {
            return self.seen;
        }

        let shift = new_base - self.base;
        if shift >= Self::TRACKED_LEN {
            0
        } else {
            self.seen >> shift
        }
    }
}

#[cfg(test)]
mod tests {
    use ql_wire::{RecordAck, RecordSeq};

    use super::{ReceiveOutcome, ReceivedRecords};

    fn seq(value: u64) -> RecordSeq {
        RecordSeq::from_u64(value).unwrap()
    }

    #[test]
    fn inserts_pack_contiguous_bits() {
        let mut received = ReceivedRecords::default();

        assert_eq!(
            received.insert(seq(10)),
            ReceiveOutcome::New {
                out_of_order: false
            }
        );
        assert_eq!(
            received.insert(seq(12)),
            ReceiveOutcome::New { out_of_order: true }
        );
        assert_eq!(
            received.insert(seq(11)),
            ReceiveOutcome::New { out_of_order: true }
        );

        let ack = received.ack().unwrap();
        assert_eq!(
            ack,
            RecordAck {
                base_seq: seq(10),
                bits: 0b111,
            }
        );
    }

    #[test]
    fn old_records_fall_out_of_fixed_window() {
        let mut received = ReceivedRecords::default();

        assert_eq!(
            received.insert(seq(0)),
            ReceiveOutcome::New {
                out_of_order: false
            }
        );
        assert_eq!(
            received.insert(seq(300)),
            ReceiveOutcome::New { out_of_order: true }
        );
        assert_eq!(received.insert(seq(0)), ReceiveOutcome::TooOld);

        let ack = received.ack().unwrap();
        assert_eq!(
            ack,
            RecordAck {
                base_seq: seq(237),
                bits: 1u64 << 63,
            }
        );
    }

    #[test]
    fn duplicate_in_window_is_rejected() {
        let mut received = ReceivedRecords::default();

        assert_eq!(
            received.insert(seq(7)),
            ReceiveOutcome::New {
                out_of_order: false
            }
        );
        assert_eq!(received.insert(seq(7)), ReceiveOutcome::Duplicate);
    }

    #[test]
    fn sliding_window_preserves_relative_bits() {
        let mut received = ReceivedRecords::default();

        assert_eq!(
            received.insert(seq(10)),
            ReceiveOutcome::New {
                out_of_order: false
            }
        );
        assert_eq!(
            received.insert(seq(12)),
            ReceiveOutcome::New { out_of_order: true }
        );
        assert_eq!(
            received.insert(seq(70)),
            ReceiveOutcome::New { out_of_order: true }
        );

        let ack = received.ack().unwrap();
        assert_eq!(
            ack,
            RecordAck {
                base_seq: seq(10),
                bits: (1u64 << 0) | (1u64 << 2) | (1u64 << 60),
            }
        );
    }
}
