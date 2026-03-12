use std::time::Instant;

use super::{OpenId, Token};
use crate::{
    wire::stream::{
        Direction, ResetCode, ResetTarget, StreamFrame, StreamFrameReset, StreamMessage,
    },
    StreamId, StreamSeq,
};

#[derive(Debug)]
pub struct StreamMeta {
    pub stream_id: StreamId,
    pub last_activity: Instant,
}

#[derive(Debug)]
pub struct PendingPull {
    pub offset: u64,
    pub max_len: usize,
}

#[derive(Debug)]
pub struct OutboundState {
    pub dir: Direction,
    pub sent_offset: u64,
    pub final_offset: Option<u64>,
    pub closed: bool,
    pub pending_pull: Option<PendingPull>,
}

impl OutboundState {
    pub fn new(dir: Direction) -> Self {
        Self {
            dir,
            sent_offset: 0,
            final_offset: None,
            closed: false,
            pending_pull: None,
        }
    }

    pub fn can_request_data(&self) -> bool {
        !self.closed
            && self.pending_pull.is_none()
            && self
                .final_offset
                .is_none_or(|final_offset| self.sent_offset < final_offset)
    }
}

#[derive(Debug)]
pub struct InboundState {
    pub next_offset: u64,
    pub closed: bool,
}

impl InboundState {
    pub fn new() -> Self {
        Self {
            next_offset: 0,
            closed: false,
        }
    }
}

#[derive(Debug)]
pub struct OpenWaiter {
    pub open_id: Option<OpenId>,
    pub open_timeout_token: Token,
}

#[derive(Debug)]
pub enum InitiatorAccept {
    Opening(OpenWaiter),
    WaitingAccept(OpenWaiter),
    Open { response_head: Vec<u8> },
}

#[derive(Debug)]
pub struct InitiatorStream {
    pub meta: StreamMeta,
    pub control: StreamControl,
    pub request: OutboundState,
    pub response: InboundState,
    pub accept: InitiatorAccept,
}

#[derive(Debug)]
pub enum ResponderResponse {
    Pending,
    Accepted { body: OutboundState },
    Rejecting,
}

#[derive(Debug)]
pub struct ResponderStream {
    pub meta: StreamMeta,
    pub control: StreamControl,
    pub request: InboundState,
    pub response: ResponderResponse,
}

#[derive(Debug)]
pub enum StreamState {
    Initiator(InitiatorStream),
    Responder(ResponderStream),
}

impl StreamState {
    pub fn stream_id(&self) -> StreamId {
        match self {
            Self::Initiator(state) => state.meta.stream_id,
            Self::Responder(state) => state.meta.stream_id,
        }
    }

    pub fn last_activity_mut(&mut self) -> &mut Instant {
        match self {
            Self::Initiator(state) => &mut state.meta.last_activity,
            Self::Responder(state) => &mut state.meta.last_activity,
        }
    }

    pub fn control(&self) -> &StreamControl {
        match self {
            Self::Initiator(state) => &state.control,
            Self::Responder(state) => &state.control,
        }
    }

    pub fn control_mut(&mut self) -> &mut StreamControl {
        match self {
            Self::Initiator(state) => &mut state.control,
            Self::Responder(state) => &mut state.control,
        }
    }

    pub fn outbound_mut(&mut self, dir: Direction) -> Option<&mut OutboundState> {
        match self {
            Self::Initiator(state) if dir == Direction::Request => Some(&mut state.request),
            Self::Responder(state) if dir == Direction::Response => match &mut state.response {
                ResponderResponse::Accepted { body } => Some(body),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn inbound_mut(&mut self, dir: Direction) -> Option<&mut InboundState> {
        match self {
            Self::Initiator(state) if dir == Direction::Response => Some(&mut state.response),
            Self::Responder(state) if dir == Direction::Request => Some(&mut state.request),
            _ => None,
        }
    }

    pub fn open_timeout_token(&self) -> Option<Token> {
        match self {
            Self::Initiator(state) => match &state.accept {
                InitiatorAccept::Opening(waiter) | InitiatorAccept::WaitingAccept(waiter) => {
                    Some(waiter.open_timeout_token)
                }
                InitiatorAccept::Open { .. } => None,
            },
            _ => None,
        }
    }

    pub fn can_reap(&self) -> bool {
        if self.control().awaiting.is_some()
            || !self.control().pending.is_empty()
            || self.control().pending_ack_seq.is_some()
        {
            return false;
        }
        match self {
            Self::Initiator(state) => {
                matches!(state.accept, InitiatorAccept::Open { .. })
                    && state.request.closed
                    && state.response.closed
            }
            Self::Responder(state) => match &state.response {
                ResponderResponse::Accepted { body } => state.request.closed && body.closed,
                ResponderResponse::Rejecting => true,
                ResponderResponse::Pending => false,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct AwaitingMessage {
    pub tx_seq: StreamSeq,
    pub frame: StreamFrame,
    pub attempt: u8,
}

#[derive(Debug, Default)]
pub struct PendingFrames {
    pub setup: Option<StreamFrame>,
    pub reset: Option<StreamFrameReset>,
}

impl PendingFrames {
    pub fn take_next_control(&mut self, stream_id: StreamId) -> Option<StreamFrame> {
        if let Some(frame) = self.setup.take() {
            return Some(frame);
        }
        if let Some(reset) = self.reset.take() {
            return Some(StreamFrame::Reset(StreamFrameReset { stream_id, ..reset }));
        }
        None
    }

    pub fn set_setup(&mut self, frame: StreamFrame) {
        self.setup = Some(frame);
    }

    pub fn set_reset(&mut self, target: ResetTarget, code: ResetCode) {
        self.reset = Some(StreamFrameReset {
            stream_id: StreamId(0),
            target,
            code,
        });
    }

    pub fn is_empty(&self) -> bool {
        self.setup.is_none() && self.reset.is_none()
    }
}

#[derive(Debug)]
pub struct StreamControl {
    pub pending: PendingFrames,
    pub awaiting: Option<AwaitingMessage>,
    pub next_tx_seq: StreamSeq,
    pub next_rx_seq: StreamSeq,
    pub pending_ack_seq: Option<StreamSeq>,
}

impl Default for StreamControl {
    fn default() -> Self {
        Self {
            pending: PendingFrames::default(),
            awaiting: None,
            next_tx_seq: StreamSeq(1),
            next_rx_seq: StreamSeq(1),
            pending_ack_seq: None,
        }
    }
}

impl StreamControl {
    pub fn take_tx_seq(&mut self) -> StreamSeq {
        let tx_seq = self.next_tx_seq;
        self.next_tx_seq = StreamSeq(self.next_tx_seq.0.wrapping_add(1));
        tx_seq
    }

    pub fn mark_ack(&mut self, ack_seq: StreamSeq) {
        self.pending_ack_seq = Some(ack_seq);
    }

    pub fn take_ack_seq(&mut self) -> Option<StreamSeq> {
        self.pending_ack_seq.take()
    }
}

#[derive(Debug)]
pub enum QueuedPayload {
    PreEncoded(Vec<u8>),
    Stream {
        /// Whether the peer must acknowledge this write so the engine tracks
        /// it for retransmit and stream-level delivery timeout handling.
        track_ack: bool,
        message: StreamMessage,
    },
}

#[derive(Debug)]
pub struct QueuedWrite {
    pub token: Token,
    pub payload: QueuedPayload,
}
