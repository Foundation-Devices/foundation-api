use std::{collections::VecDeque, time::Instant};

use indexmap::IndexMap;
use ql_wire::{
    CloseTarget, SessionAck, SessionBody, SessionCloseBody, SessionSeq, StreamClose, StreamId,
};

use super::{
    ring::SeqRing,
    stream_window::StreamRecvWindow,
    SessionEvent,
    SessionState,
};

pub const SESSION_WINDOW_CAPACITY: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRole {
    Initiator,
    Responder,
}

impl StreamRole {
    pub fn outbound_target(self) -> CloseTarget {
        match self {
            Self::Initiator => CloseTarget::Request,
            Self::Responder => CloseTarget::Response,
        }
    }

    pub fn inbound_target(self) -> CloseTarget {
        match self {
            Self::Initiator => CloseTarget::Response,
            Self::Responder => CloseTarget::Request,
        }
    }
}

#[derive(Debug, Clone)]
pub enum OutboundState {
    Open,
    FinQueued,
    Finished,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamOpenState {
    PendingSend,
    WaitingForAck,
    Opened,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundState {
    Open,
    Finished,
    Closed(StreamClose),
    Discarding,
}

#[derive(Debug)]
pub struct StreamState {
    pub role: StreamRole,
    pub open_state: StreamOpenState,
    pub send_buf: VecDeque<u8>,
    pub pending_close: Option<StreamClose>,
    pub recv_buf: VecDeque<u8>,
    pub recv_window: StreamRecvWindow,
    pub next_send_chunk_seq: u64,
    pub outbound_state: OutboundState,
    pub inbound_state: InboundState,
}

impl StreamState {
    pub fn new(role: StreamRole) -> Self {
        Self {
            role,
            open_state: match role {
                StreamRole::Initiator => StreamOpenState::PendingSend,
                StreamRole::Responder => StreamOpenState::Opened,
            },
            send_buf: VecDeque::new(),
            pending_close: None,
            recv_buf: VecDeque::new(),
            recv_window: StreamRecvWindow::new(),
            next_send_chunk_seq: 0,
            outbound_state: OutboundState::Open,
            inbound_state: InboundState::Open,
        }
    }

    pub fn is_writable(&self) -> bool {
        matches!(self.outbound_state, OutboundState::Open)
    }
}

#[derive(Debug, Clone)]
pub struct PendingSessionBody {
    pub body: SessionBody,
    /// whether the body should be retransmitted after a confirmed send times out without ack
    pub retransmit: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PendingSessionControl {
    pub ping: bool,
    pub close: Option<SessionCloseBody>,
}

#[derive(Debug, Clone)]
pub struct TxEntry {
    pub pending: PendingSessionBody,
    pub state: TxState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxState {
    Pending,
    Issued,
    Sent { sent_at: Instant },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckState {
    Idle,
    Delayed { due_at: Instant },
    Immediate,
}

pub struct SessionFsmState {
    pub now: Instant,
    pub last_activity_at: Instant,
    pub last_inbound_at: Instant,
    pub session_state: SessionState,
    pub next_stream_ordinal: u32,
    pub next_seq: SessionSeq,
    pub tx_ring: SeqRing<SESSION_WINDOW_CAPACITY, TxEntry>,
    pub rx_ring: SeqRing<SESSION_WINDOW_CAPACITY, ()>,
    pub ack_state: AckState,
    pub pending_control: PendingSessionControl,
    /// `IndexMap` has stable (and fast) iteration order for round-robin
    /// scheduling, so we do not need a separate ready queue
    pub streams: IndexMap<StreamId, StreamState>,
    pub next_stream_index: usize,
    pub events: VecDeque<SessionEvent>,
}

impl SessionFsmState {
    pub fn current_ack(&self) -> SessionAck {
        SessionAck {
            base: SessionSeq(self.rx_ring.base_seq().0.saturating_sub(1)),
            bitmap: self.rx_ring.bitmap(),
        }
    }

    pub fn clear_ack_schedule(&mut self) {
        self.ack_state = AckState::Idle;
    }
}
