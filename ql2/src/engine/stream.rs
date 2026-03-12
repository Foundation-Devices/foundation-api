use std::{
    collections::{BTreeMap, VecDeque},
    time::Instant,
};

use super::{OpenId, Token};
use crate::{
    StreamId, StreamSeq,
    wire::stream::{
        Direction, ResetCode, ResetTarget, StreamAck, StreamBody, StreamFrame, StreamFrameReset,
    },
};

pub const STREAM_WINDOW_SIZE: u32 = 8;
pub const STREAM_ACK_EAGER_THRESHOLD: u32 = STREAM_WINDOW_SIZE / 2;

#[derive(Debug)]
pub struct StreamMeta {
    pub stream_id: StreamId,
    pub last_activity: Instant,
}

#[derive(Debug)]
pub struct PendingPull {
    pub offset: u64,
}

#[derive(Debug)]
pub struct OutboundState {
    pub dir: Direction,
    pub sent_offset: u64,
    pub final_offset: Option<u64>,
    pub closed: bool,
    pub pending_pull: Option<PendingPull>,
    pub fin_queued: bool,
}

impl OutboundState {
    pub fn new(dir: Direction) -> Self {
        Self {
            dir,
            sent_offset: 0,
            final_offset: None,
            closed: false,
            pending_pull: None,
            fin_queued: false,
        }
    }

    pub fn can_request_data(&self) -> bool {
        !self.closed
            && self.pending_pull.is_none()
            && self
                .final_offset
                .is_none_or(|final_offset| self.sent_offset < final_offset)
    }

    pub fn needs_fin_frame(&self) -> bool {
        !self.closed
            && !self.fin_queued
            && self.pending_pull.is_none()
            && self
                .final_offset
                .is_some_and(|final_offset| final_offset == self.sent_offset)
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
pub struct InFlightFrame {
    pub tx_seq: StreamSeq,
    pub frame: StreamFrame,
    pub attempt: u8,
}

#[derive(Debug)]
pub enum BufferIncomingResult {
    Duplicate,
    AlreadyBuffered,
    Buffered { out_of_order: bool },
    OutOfWindow,
}

#[derive(Debug)]
pub struct StreamControl {
    pub pending: VecDeque<StreamFrame>,
    pub in_flight: BTreeMap<StreamSeq, InFlightFrame>,
    pub next_tx_seq: StreamSeq,
    pub committed_rx_seq: StreamSeq,
    pub recv_buffer: BTreeMap<StreamSeq, StreamFrame>,
    pub ack_dirty: bool,
    pub ack_immediate: bool,
    pub ack_delay_token: Option<Token>,
    pub ack_outbound_token: Option<Token>,
    pub last_sent_ack_base: StreamSeq,
}

impl Default for StreamControl {
    fn default() -> Self {
        Self {
            pending: VecDeque::new(),
            in_flight: BTreeMap::new(),
            next_tx_seq: StreamSeq(1),
            committed_rx_seq: StreamSeq(0),
            recv_buffer: BTreeMap::new(),
            ack_dirty: false,
            ack_immediate: false,
            ack_delay_token: None,
            ack_outbound_token: None,
            last_sent_ack_base: StreamSeq(0),
        }
    }
}

impl StreamControl {
    pub fn take_tx_seq(&mut self) -> StreamSeq {
        let tx_seq = self.next_tx_seq;
        self.next_tx_seq = StreamSeq(self.next_tx_seq.0.wrapping_add(1));
        tx_seq
    }

    pub fn send_window_has_space(&self) -> bool {
        self.in_flight.len() < STREAM_WINDOW_SIZE as usize
    }

    pub fn queue_frame_back(&mut self, frame: StreamFrame) {
        self.pending.push_back(frame);
    }

    pub fn queue_frame_front(&mut self, frame: StreamFrame) {
        self.pending.push_front(frame);
    }

    pub fn note_ack(&mut self, immediate: bool) {
        self.ack_dirty = true;
        self.ack_immediate |= immediate;
    }

    pub fn clear_ack_schedule(&mut self) {
        self.ack_dirty = false;
        self.ack_immediate = false;
        self.ack_delay_token = None;
    }

    pub fn maybe_force_ack_for_progress(&mut self) {
        if !self.ack_dirty {
            return;
        }
        let progressed = self
            .committed_rx_seq
            .0
            .saturating_sub(self.last_sent_ack_base.0);
        if progressed >= STREAM_ACK_EAGER_THRESHOLD {
            self.ack_immediate = true;
        }
    }

    pub fn note_ack_sent(&mut self, ack: StreamAck) {
        if ack.base.0 > self.last_sent_ack_base.0 {
            self.last_sent_ack_base = ack.base;
        }
    }

    pub fn current_ack(&self) -> StreamAck {
        let mut bitmap = 0u8;
        for tx_seq in self.recv_buffer.keys().copied() {
            let delta = tx_seq.0.saturating_sub(self.committed_rx_seq.0);
            if (1..=STREAM_WINDOW_SIZE).contains(&delta) {
                bitmap |= 1u8 << (delta - 1);
            }
        }
        StreamAck {
            base: self.committed_rx_seq,
            bitmap,
        }
    }

    pub fn buffer_incoming(
        &mut self,
        tx_seq: StreamSeq,
        frame: StreamFrame,
    ) -> BufferIncomingResult {
        if tx_seq.0 <= self.committed_rx_seq.0 {
            return BufferIncomingResult::Duplicate;
        }

        let delta = tx_seq.0.saturating_sub(self.committed_rx_seq.0);
        if !(1..=STREAM_WINDOW_SIZE).contains(&delta) {
            return BufferIncomingResult::OutOfWindow;
        }

        if self.recv_buffer.contains_key(&tx_seq) {
            return BufferIncomingResult::AlreadyBuffered;
        }

        let out_of_order = delta > 1;
        self.recv_buffer.insert(tx_seq, frame);
        BufferIncomingResult::Buffered { out_of_order }
    }

    pub fn pop_next_committable(&mut self) -> Option<(StreamSeq, StreamFrame)> {
        let next_seq = StreamSeq(self.committed_rx_seq.0.wrapping_add(1));
        let frame = self.recv_buffer.remove(&next_seq)?;
        self.committed_rx_seq = next_seq;
        Some((next_seq, frame))
    }

    pub fn ack_covers(ack: StreamAck, tx_seq: StreamSeq) -> bool {
        if tx_seq.0 <= ack.base.0 {
            return true;
        }
        let delta = tx_seq.0.saturating_sub(ack.base.0);
        if !(1..=STREAM_WINDOW_SIZE).contains(&delta) {
            return false;
        }
        (ack.bitmap & (1u8 << (delta - 1))) != 0
    }
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
pub struct ProvisionalStream {
    pub meta: StreamMeta,
    pub control: StreamControl,
    pub timeout_token: Token,
}

#[derive(Debug)]
pub enum StreamState {
    Initiator(InitiatorStream),
    Responder(ResponderStream),
    Provisional(ProvisionalStream),
}

impl StreamState {
    pub fn stream_id(&self) -> StreamId {
        match self {
            Self::Initiator(state) => state.meta.stream_id,
            Self::Responder(state) => state.meta.stream_id,
            Self::Provisional(state) => state.meta.stream_id,
        }
    }

    pub fn last_activity_mut(&mut self) -> &mut Instant {
        match self {
            Self::Initiator(state) => &mut state.meta.last_activity,
            Self::Responder(state) => &mut state.meta.last_activity,
            Self::Provisional(state) => &mut state.meta.last_activity,
        }
    }

    pub fn control(&self) -> &StreamControl {
        match self {
            Self::Initiator(state) => &state.control,
            Self::Responder(state) => &state.control,
            Self::Provisional(state) => &state.control,
        }
    }

    pub fn control_mut(&mut self) -> &mut StreamControl {
        match self {
            Self::Initiator(state) => &mut state.control,
            Self::Responder(state) => &mut state.control,
            Self::Provisional(state) => &mut state.control,
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

    pub fn provisional_timeout_token(&self) -> Option<Token> {
        match self {
            Self::Provisional(state) => Some(state.timeout_token),
            _ => None,
        }
    }

    pub fn is_provisional(&self) -> bool {
        matches!(self, Self::Provisional(_))
    }

    pub fn can_reap(&self) -> bool {
        if !self.control().pending.is_empty()
            || !self.control().in_flight.is_empty()
            || !self.control().recv_buffer.is_empty()
            || self.control().ack_dirty
            || self.control().ack_outbound_token.is_some()
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
            Self::Provisional(_) => false,
        }
    }
}

#[derive(Debug)]
pub enum QueuedPayload {
    PreEncoded(Vec<u8>),
    Stream { body: StreamBody },
}

#[derive(Debug)]
pub struct QueuedWrite {
    pub token: Token,
    pub payload: QueuedPayload,
}

pub fn reset_frame(stream_id: StreamId, target: ResetTarget, code: ResetCode) -> StreamFrame {
    StreamFrame::Reset(StreamFrameReset {
        stream_id,
        target,
        code,
    })
}
