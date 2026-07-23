//! outbound record tracking state for ack and retransmit handling

use std::time::{Duration, Instant};

use ql_common::StreamId;
use ql_wire::{RecordAck, RecordSeq, StreamReset};

#[derive(Debug, Clone)]
pub struct TrackedRecord {
    pub seq: RecordSeq,
    pub frames: Vec<TrackedFrame>,
    pub ack: Option<RecordAck>,
    pub ping_included: bool,
    pub window_updates: Vec<(StreamId, u64)>,
    pub sent_at: Option<Instant>,
}

#[derive(Debug, Clone)]
pub enum TrackedFrame {
    StreamData(TrackedStreamData),
    StreamReset(StreamReset),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackedStreamData {
    pub stream_id: StreamId,
    pub offset: u64,
    pub len: usize,
    pub fin: bool,
}

/// estimates RTO from smoothed RTT and variance
/// backs off on timeout, and resets on ACK
pub struct LossRecovery {
    smoothed_rtt: Option<Duration>,
    rtt_variance: Duration,
    base_rto: Duration,
    rto: Duration,
}

impl LossRecovery {
    const MIN_RTO: Duration = Duration::from_millis(10);
    const MAX_RTO: Duration = Duration::from_secs(30);

    pub fn new(initial_rto: Duration) -> Self {
        let rto = initial_rto.clamp(Self::MIN_RTO, Self::MAX_RTO);
        Self {
            smoothed_rtt: None,
            rtt_variance: Duration::ZERO,
            base_rto: rto,
            rto,
        }
    }

    pub fn rto(&self) -> Duration {
        self.rto
    }

    pub fn on_ack(&mut self, sample: Duration) {
        let (smoothed_rtt, rtt_variance) = match self.smoothed_rtt {
            Some(smoothed_rtt) => (
                smoothed_rtt.saturating_mul(7).saturating_add(sample) / 8,
                self.rtt_variance
                    .saturating_mul(3)
                    .saturating_add(smoothed_rtt.abs_diff(sample))
                    / 4,
            ),
            None => (sample, sample / 2),
        };
        self.smoothed_rtt = Some(smoothed_rtt);
        self.rtt_variance = rtt_variance;
        self.base_rto = smoothed_rtt
            .saturating_add(rtt_variance.saturating_mul(4))
            .clamp(Self::MIN_RTO, Self::MAX_RTO);
        self.rto = self.base_rto;
    }

    pub fn on_timeout(&mut self) {
        self.rto = self.rto.saturating_mul(2).min(Self::MAX_RTO);
    }
}
