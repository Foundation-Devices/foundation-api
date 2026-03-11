use std::time::Instant;

use super::{OpenId, Token};
use crate::{
    wire::stream::{
        Direction, ResetCode, ResetTarget, StreamBody, StreamFrame, StreamFrameAccept,
        StreamFrameCredit, StreamFrameOpen, StreamFrameReject, StreamFrameReset,
    },
    PacketId, StreamId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamKey {
    pub stream_id: StreamId,
}

#[derive(Debug)]
pub struct StreamMeta {
    pub key: StreamKey,
    pub request_head: Vec<u8>,
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
    pub remote_max_offset: u64,
    pub sent_offset: u64,
    pub released_offset: u64,
    pub final_offset: Option<u64>,
    pub data_enabled: bool,
    pub closed: bool,
    pub pending_pull: Option<PendingPull>,
}

impl OutboundState {
    pub fn new(dir: Direction, remote_max_offset: u64, data_enabled: bool) -> Self {
        Self {
            dir,
            remote_max_offset,
            sent_offset: 0,
            released_offset: 0,
            final_offset: None,
            data_enabled,
            closed: false,
            pending_pull: None,
        }
    }

    pub fn can_request_data(&self) -> bool {
        self.data_enabled
            && !self.closed
            && self.pending_pull.is_none()
            && self.sent_offset < self.remote_max_offset
            && self
                .final_offset
                .is_none_or(|final_offset| self.sent_offset < final_offset)
    }
}

#[derive(Debug)]
pub struct InboundState {
    pub next_offset: u64,
    pub max_offset: u64,
    pub closed: bool,
}

impl InboundState {
    pub fn new(max_offset: u64) -> Self {
        Self {
            next_offset: 0,
            max_offset,
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
    Pending {
        initial_credit: u64,
    },
    Accepted {
        initial_credit: u64,
        body: OutboundState,
    },
    Rejecting {
        initial_credit: u64,
    },
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
    pub fn key(&self) -> StreamKey {
        match self {
            Self::Initiator(state) => state.meta.key,
            Self::Responder(state) => state.meta.key,
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
                ResponderResponse::Accepted { body, .. } => Some(body),
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
        if self.control().awaiting.is_some() || !self.control().pending.is_empty() {
            return false;
        }
        match self {
            Self::Initiator(state) => {
                matches!(state.accept, InitiatorAccept::Open { .. })
                    && state.request.closed
                    && state.response.closed
            }
            Self::Responder(state) => match &state.response {
                ResponderResponse::Accepted { body, .. } => state.request.closed && body.closed,
                ResponderResponse::Rejecting { .. } => true,
                ResponderResponse::Pending { .. } => false,
            },
        }
    }
}

#[derive(Debug)]
pub struct AwaitingPacket {
    pub packet_id: PacketId,
    pub frame: AwaitingFrame,
    pub attempt: u8,
}

#[derive(Debug, Clone)]
pub enum AwaitingFrame {
    Control(StreamFrame),
    Data {
        dir: Direction,
        offset: u64,
        len: usize,
    },
}

#[derive(Debug)]
pub enum SetupFrame {
    Open(StreamFrameOpen),
    Accept(StreamFrameAccept),
    Reject(StreamFrameReject),
}

#[derive(Debug)]
pub struct PendingFrames {
    pub setup: Option<SetupFrame>,
    pub credit: Option<StreamFrameCredit>,
    pub reset: Option<StreamFrameReset>,
}

impl PendingFrames {
    pub fn new() -> Self {
        Self {
            setup: None,
            credit: None,
            reset: None,
        }
    }

    pub fn take_next_control(&mut self, stream_id: StreamId) -> Option<StreamFrame> {
        if let Some(setup) = self.setup.take() {
            return Some(match setup {
                SetupFrame::Open(frame) => StreamFrame::Open(frame),
                SetupFrame::Accept(frame) => StreamFrame::Accept(frame),
                SetupFrame::Reject(frame) => StreamFrame::Reject(frame),
            });
        }
        if let Some(reset) = self.reset.take() {
            return Some(StreamFrame::Reset(StreamFrameReset { stream_id, ..reset }));
        }
        self.credit.take().map(StreamFrame::Credit)
    }

    pub fn set_setup(&mut self, setup: SetupFrame) {
        self.setup = Some(setup);
    }

    pub fn set_credit(&mut self, frame: StreamFrameCredit) {
        if self.reset.is_none() {
            self.credit = Some(frame);
        }
    }

    pub fn set_reset(&mut self, dir: ResetTarget, code: ResetCode) {
        self.credit = None;
        self.reset = Some(StreamFrameReset {
            stream_id: StreamId(0),
            dir,
            code,
        });
    }

    pub fn is_empty(&self) -> bool {
        self.setup.is_none() && self.credit.is_none() && self.reset.is_none()
    }
}

#[derive(Debug)]
pub struct StreamControl {
    pub pending: PendingFrames,
    pub awaiting: Option<AwaitingPacket>,
}

impl StreamControl {
    pub fn new() -> Self {
        Self {
            pending: PendingFrames::new(),
            awaiting: None,
        }
    }
}

#[derive(Debug)]
pub enum QueuedPayload {
    PreEncoded(Vec<u8>),
    StreamBody(StreamBody),
}

#[derive(Debug)]
pub struct QueuedWrite {
    pub token: Token,
    pub stream_id: Option<StreamId>,
    pub packet_id: Option<PacketId>,
    pub track_ack: bool,
    pub payload: QueuedPayload,
}
