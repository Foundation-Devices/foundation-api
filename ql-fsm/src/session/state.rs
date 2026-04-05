use std::time::Instant;

use indexmap::IndexMap;
use ql_wire::{CloseTarget, RecordSeq, SessionClose, StreamClose, StreamId};

use super::{
    received_records::ReceivedRecords, stream_rx::StreamRx, stream_tx::StreamTx,
    tracked::TrackedRecord, SessionState,
};

pub struct SessionFsmState {
    pub now: Instant,
    pub last_activity_at: Instant,
    pub last_inbound_at: Instant,
    pub session_state: SessionState,
    pub next_stream_ordinal: u32,
    pub next_record_seq: RecordSeq,
    pub next_write_id: u64,
    pub tracked_records: IndexMap<u64, TrackedRecord>,
    pub received_records: ReceivedRecords,
    pub ack_state: AckState,
    pub pending_control: PendingSessionControl,
    pub streams: IndexMap<StreamId, StreamState>,
    pub next_stream_index: usize,
}

#[derive(Debug)]
pub struct StreamState {
    pub role: StreamRole,
    pub rx: StreamRx,
    pub tx: StreamTx,
    pub pending_close: Option<StreamClose>,
    pub peer_max_offset: u64,
    pub outbound_state: OutboundState,
    pub inbound_state: InboundState,
    pub advertised_max_offset: u64,
    pub pending_window: bool,
}

impl StreamState {
    pub fn new(
        role: StreamRole,
        receive_buffer_size: usize,
        initial_peer_stream_receive_window: u32,
    ) -> Self {
        Self {
            role,
            tx: StreamTx::new(),
            pending_close: None,
            peer_max_offset: initial_peer_stream_receive_window as u64,
            outbound_state: OutboundState::Open,
            inbound_state: InboundState::Open,
            rx: StreamRx::new(receive_buffer_size),
            advertised_max_offset: receive_buffer_size as u64,
            pending_window: false,
        }
    }

    pub fn is_writable(&self) -> bool {
        matches!(self.outbound_state, OutboundState::Open)
    }

    pub fn buffered_send_bytes(&self) -> usize {
        self.tx.buffered_len()
    }

    pub fn send_capacity(&self, send_buffer_size: usize) -> usize {
        send_buffer_size.saturating_sub(self.buffered_send_bytes())
    }

    pub fn readable_bytes(&self) -> usize {
        self.rx.readable_len()
    }

    pub fn recv_limit(&self) -> u64 {
        self.rx
            .start_offset()
            .saturating_add(self.rx.max_buffered() as u64)
    }

    pub fn reset_recv(&mut self) {
        self.rx = StreamRx::with_start_offset(self.rx.start_offset(), self.rx.max_buffered());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRole {
    Initiator,
    Responder,
}

impl StreamRole {
    pub fn outbound_target(self) -> CloseTarget {
        match self {
            Self::Initiator => CloseTarget::Origin,
            Self::Responder => CloseTarget::Return,
        }
    }

    pub fn inbound_target(self) -> CloseTarget {
        match self {
            Self::Initiator => CloseTarget::Return,
            Self::Responder => CloseTarget::Origin,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundState {
    Open,
    FinQueued,
    Finished,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundState {
    Open,
    Finished,
    Closed(StreamClose),
    Discarding,
}

#[derive(Debug, Clone, Default)]
pub struct PendingSessionControl {
    pub ping: bool,
    pub close: Option<SessionClose>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckState {
    // ack state is not dirty
    Idle,
    // ack is dirty. we can wait to piggy back on an outgoing record until this time
    Dirty { due_at: Instant },
}
