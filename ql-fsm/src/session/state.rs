use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    time::Instant,
};

use ql_wire::{
    CloseTarget, SessionAck, SessionBody, SessionCloseBody, SessionSeq, StreamCloseFrame,
    StreamFrame, StreamId,
};

use super::{ring::SeqRing, SessionEvent, SessionState, StreamIncoming};

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
pub struct PendingChunk {
    pub bytes: Vec<u8>,
    pub fin: bool,
}

impl PendingChunk {
    pub fn end_offset(&self, offset: u64) -> u64 {
        offset + self.bytes.len() as u64
    }
}

#[derive(Debug, Clone)]
pub enum PendingStreamBody {
    Stream(StreamFrame),
    StreamClose(StreamCloseFrame),
}

impl PendingStreamBody {
    pub fn to_session_body(&self) -> SessionBody {
        match self {
            Self::Stream(frame) => SessionBody::Stream(frame.clone()),
            Self::StreamClose(frame) => SessionBody::StreamClose(frame.clone()),
        }
    }
}

#[derive(Debug)]
pub struct StreamState {
    pub role: StreamRole,
    pub send_queue: VecDeque<PendingStreamBody>,
    pub inbound_queue: VecDeque<StreamIncoming>,
    pub pending_recv: BTreeMap<u64, PendingChunk>,
    pub next_send_offset: u64,
    pub next_recv_offset: u64,
    pub outbound_finished: bool,
    pub outbound_closed: bool,
    pub inbound_finished: bool,
    pub inbound_closed: bool,
    pub inbound_discarding: bool,
    pub ready_enqueued: bool,
}

impl StreamState {
    pub fn new(role: StreamRole) -> Self {
        Self {
            role,
            send_queue: VecDeque::new(),
            inbound_queue: VecDeque::new(),
            pending_recv: BTreeMap::new(),
            next_send_offset: 0,
            next_recv_offset: 0,
            outbound_finished: false,
            outbound_closed: false,
            inbound_finished: false,
            inbound_closed: false,
            inbound_discarding: false,
            ready_enqueued: false,
        }
    }

    pub fn is_writable(&self) -> bool {
        !self.outbound_finished && !self.outbound_closed
    }
}

#[derive(Debug, Clone)]
pub struct PendingSessionBody {
    pub body: SessionBody,
    pub retransmit: bool,
    pub priority: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PendingSessionControl {
    pub ping: bool,
    pub unpair: bool,
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
    pub streams: HashMap<StreamId, StreamState>,
    pub ready_streams: VecDeque<StreamId>,
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
