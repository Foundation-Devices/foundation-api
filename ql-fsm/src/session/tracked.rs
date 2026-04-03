//! outbound record tracking state for ack and retransmit handling

use std::time::Instant;

use ql_wire::{RecordSeq, SessionClose, StreamClose, StreamId};

#[derive(Debug, Clone)]
pub struct TrackedRecord {
    pub seq: RecordSeq,
    pub frames: Vec<TrackedFrame>,
    pub ack_included: bool,
    pub ping_included: bool,
    pub window_updates: Vec<(StreamId, u64)>,
    pub sent_at: Option<Instant>,
}

#[derive(Debug, Clone)]
pub enum TrackedFrame {
    StreamData(TrackedStreamData),
    StreamClose(StreamClose),
    Close(SessionClose),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackedStreamData {
    pub stream_id: StreamId,
    pub offset: u64,
    pub len: usize,
    pub fin: bool,
}
