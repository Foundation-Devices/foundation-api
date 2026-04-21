//! outbound record tracking state for ack and retransmit handling

use std::time::Instant;

use ql_wire::{RecordAck, RecordSeq, StreamClose, StreamId};

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
    StreamClose(StreamClose),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackedStreamData {
    pub stream_id: StreamId,
    pub offset: u64,
    pub len: usize,
    pub fin: bool,
}
