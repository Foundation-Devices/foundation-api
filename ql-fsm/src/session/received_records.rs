use ql_wire::{RecordAck, RecordSeq};

#[derive(Debug, Default)]
pub struct ReceivedRecords {
    seen: u64,
    base: u64,
    largest: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveOutcome {
    New { out_of_order: bool },
    Duplicate,
}

impl ReceivedRecords {
    const TRACKED_LEN: u64 = RecordAck::BITMAP_BITS as u64;
    const TRACKED_WINDOW: u64 = Self::TRACKED_LEN - 1;

    pub fn insert(&mut self, seq: RecordSeq) -> ReceiveOutcome {
        let seq = seq.0;
        let Some(largest) = self.largest else {
            self.base = seq;
            self.seen = 1;
            self.largest = Some(seq);
            return ReceiveOutcome::New {
                out_of_order: false,
            };
        };

        if largest.saturating_sub(seq) > Self::TRACKED_WINDOW {
            return ReceiveOutcome::Duplicate;
        }

        let out_of_order = seq != largest.saturating_add(1);
        if seq > largest {
            self.advance_base(seq.saturating_sub(Self::TRACKED_WINDOW));
            self.largest = Some(seq);
        }

        let Some(bit) = self.bit_for(seq) else {
            return ReceiveOutcome::Duplicate;
        };
        if self.seen & bit != 0 {
            return ReceiveOutcome::Duplicate;
        }

        self.seen |= bit;
        ReceiveOutcome::New { out_of_order }
    }

    pub fn ack(&self) -> Option<RecordAck> {
        (self.seen != 0).then_some(RecordAck {
            base_seq: RecordSeq(self.base),
            bits: self.seen,
        })
    }

    fn bit_for(&self, seq: u64) -> Option<u64> {
        if seq < self.base {
            return None;
        }

        let offset = seq - self.base;
        (offset < Self::TRACKED_LEN).then_some(1u64 << offset)
    }

    fn advance_base(&mut self, new_base: u64) {
        if new_base <= self.base {
            return;
        }

        let shift = new_base - self.base;
        if shift >= Self::TRACKED_LEN {
            self.seen = 0;
        } else {
            self.seen >>= shift;
        }
        self.base = new_base;
    }
}

#[cfg(test)]
mod tests {
    use ql_wire::{RecordAck, RecordSeq};

    use super::{ReceiveOutcome, ReceivedRecords};

    #[test]
    fn inserts_pack_contiguous_bits() {
        let mut received = ReceivedRecords::default();

        assert_eq!(
            received.insert(RecordSeq(10)),
            ReceiveOutcome::New {
                out_of_order: false
            }
        );
        assert_eq!(
            received.insert(RecordSeq(12)),
            ReceiveOutcome::New { out_of_order: true }
        );
        assert_eq!(
            received.insert(RecordSeq(11)),
            ReceiveOutcome::New { out_of_order: true }
        );

        let ack = received.ack().unwrap();
        assert_eq!(
            ack,
            RecordAck {
                base_seq: RecordSeq(10),
                bits: 0b111,
            }
        );
    }

    #[test]
    fn old_records_fall_out_of_fixed_window() {
        let mut received = ReceivedRecords::default();

        assert_eq!(
            received.insert(RecordSeq(0)),
            ReceiveOutcome::New {
                out_of_order: false
            }
        );
        assert_eq!(
            received.insert(RecordSeq(300)),
            ReceiveOutcome::New { out_of_order: true }
        );
        assert_eq!(received.insert(RecordSeq(0)), ReceiveOutcome::Duplicate);

        let ack = received.ack().unwrap();
        assert_eq!(
            ack,
            RecordAck {
                base_seq: RecordSeq(237),
                bits: 1u64 << 63,
            }
        );
    }

    #[test]
    fn duplicate_in_window_is_rejected() {
        let mut received = ReceivedRecords::default();

        assert_eq!(
            received.insert(RecordSeq(7)),
            ReceiveOutcome::New {
                out_of_order: false
            }
        );
        assert_eq!(received.insert(RecordSeq(7)), ReceiveOutcome::Duplicate);
    }

    #[test]
    fn sliding_window_preserves_relative_bits() {
        let mut received = ReceivedRecords::default();

        assert_eq!(
            received.insert(RecordSeq(10)),
            ReceiveOutcome::New {
                out_of_order: false
            }
        );
        assert_eq!(
            received.insert(RecordSeq(12)),
            ReceiveOutcome::New { out_of_order: true }
        );
        assert_eq!(
            received.insert(RecordSeq(70)),
            ReceiveOutcome::New { out_of_order: true }
        );

        let ack = received.ack().unwrap();
        assert_eq!(
            ack,
            RecordAck {
                base_seq: RecordSeq(10),
                bits: (1u64 << 0) | (1u64 << 2) | (1u64 << 60),
            }
        );
    }
}
