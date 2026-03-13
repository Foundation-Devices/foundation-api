use std::{collections::VecDeque, time::Instant};

use super::{ring::SeqRing, OpenId, Token};
use crate::{
    wire::{
        stream::{
            Direction, ResetCode, ResetTarget, StreamAck, StreamBody, StreamFrame, StreamFrameReset,
        },
        StreamSeq,
    },
    StreamId,
};

pub const STREAM_WINDOW_CAPACITY: usize = 8;
pub const STREAM_WINDOW_SIZE: u32 = STREAM_WINDOW_CAPACITY as u32;
pub const STREAM_ACK_EAGER_THRESHOLD: u32 = STREAM_WINDOW_SIZE / 2;

#[derive(Debug)]
pub struct StreamMeta {
    pub stream_id: StreamId,
    pub last_activity: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundPhase {
    Ready,
    PendingPull,
    FinPending,
    FinQueued,
    Closed,
}

#[derive(Debug)]
pub struct OutboundState {
    pub dir: Direction,
    pub phase: OutboundPhase,
}

impl OutboundState {
    pub fn from_prefix(dir: Direction, fin: bool) -> Self {
        Self {
            dir,
            phase: if fin {
                OutboundPhase::FinQueued
            } else {
                OutboundPhase::Ready
            },
        }
    }

    pub fn is_closed(&self) -> bool {
        self.phase == OutboundPhase::Closed
    }

    pub fn request_data(&mut self) -> bool {
        if self.phase != OutboundPhase::Ready {
            return false;
        }
        self.phase = OutboundPhase::PendingPull;
        true
    }

    pub fn take_pending_pull(&mut self) -> bool {
        if self.phase != OutboundPhase::PendingPull {
            return false;
        }
        self.phase = OutboundPhase::Ready;
        true
    }

    pub fn finish(&mut self) {
        self.phase = match self.phase {
            OutboundPhase::Ready | OutboundPhase::PendingPull | OutboundPhase::FinPending => {
                OutboundPhase::FinPending
            }
            OutboundPhase::FinQueued => OutboundPhase::FinQueued,
            OutboundPhase::Closed => OutboundPhase::Closed,
        };
    }

    pub fn queue_fin(&mut self) -> bool {
        if self.phase != OutboundPhase::FinPending {
            return false;
        }
        self.phase = OutboundPhase::FinQueued;
        true
    }

    pub fn close(&mut self) {
        self.phase = OutboundPhase::Closed;
    }
}

#[derive(Debug)]
pub struct InboundState {
    pub closed: bool,
}

impl InboundState {
    pub fn new() -> Self {
        Self { closed: false }
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
    pub retry_at: Option<Instant>,
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
    pub in_flight: SeqRing<STREAM_WINDOW_CAPACITY, InFlightFrame>,
    pub next_tx_seq: StreamSeq,
    pub recv_buffer: SeqRing<STREAM_WINDOW_CAPACITY, StreamFrame>,
    pub ack_dirty: bool,
    pub ack_immediate: bool,
    pub ack_delay_token: Option<Token>,
    pub ack_outbound_token: Option<Token>,
    pub last_sent_ack_base: StreamSeq,
    pub fast_recovery: Option<StreamSeq>,
}

impl Default for StreamControl {
    fn default() -> Self {
        Self {
            pending: VecDeque::new(),
            in_flight: SeqRing::new(StreamSeq::START),
            next_tx_seq: StreamSeq::START,
            recv_buffer: SeqRing::new(StreamSeq::START),
            ack_dirty: false,
            ack_immediate: false,
            ack_delay_token: None,
            ack_outbound_token: None,
            last_sent_ack_base: StreamSeq(0),
            fast_recovery: None,
        }
    }
}

impl StreamControl {
    pub fn take_tx_seq(&mut self) -> StreamSeq {
        let tx_seq = self.next_tx_seq;
        self.next_tx_seq = self.next_tx_seq.next();
        tx_seq
    }

    pub fn send_window_has_space(&self) -> bool {
        self.in_flight.accepts_seq(self.next_tx_seq)
    }

    pub fn committed_rx_seq(&self) -> StreamSeq {
        self.recv_buffer.base_seq().prev()
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
        let committed = self.committed_rx_seq();
        let progressed = self
            .last_sent_ack_base
            .forward_distance_to(committed)
            .unwrap_or(0);
        if progressed >= STREAM_ACK_EAGER_THRESHOLD {
            self.ack_immediate = true;
        }
    }

    pub fn note_ack_sent(&mut self, ack: StreamAck) {
        if ack.base.serial_gt(self.last_sent_ack_base) {
            self.last_sent_ack_base = ack.base;
        }
    }

    pub fn current_ack(&self) -> StreamAck {
        StreamAck {
            base: self.committed_rx_seq(),
            bitmap: self.recv_buffer.bitmap(),
        }
    }

    pub fn buffer_incoming(
        &mut self,
        tx_seq: StreamSeq,
        frame: StreamFrame,
    ) -> BufferIncomingResult {
        if tx_seq.serial_lt(self.recv_buffer.base_seq()) {
            return BufferIncomingResult::Duplicate;
        }
        if !self.recv_buffer.accepts_seq(tx_seq) {
            return BufferIncomingResult::OutOfWindow;
        }
        if self.recv_buffer.contains_key(&tx_seq) {
            return BufferIncomingResult::AlreadyBuffered;
        }

        let out_of_order = tx_seq != self.recv_buffer.base_seq();
        let _ = self.recv_buffer.insert(tx_seq, frame);
        BufferIncomingResult::Buffered { out_of_order }
    }

    pub fn pop_next_committable(&mut self) -> Option<(StreamSeq, StreamFrame)> {
        self.recv_buffer.take_front()
    }

    pub fn insert_in_flight(&mut self, frame: InFlightFrame) {
        let _ = self.in_flight.set(frame.tx_seq, frame);
    }

    pub fn fast_retransmit_candidate(&self, ack: StreamAck, threshold: u8) -> Option<StreamSeq> {
        if threshold == 0 {
            return None;
        }

        let hole = self
            .in_flight
            .iter()
            .map(|(tx_seq, _)| tx_seq)
            .find(|tx_seq| !Self::ack_covers(ack, *tx_seq))?;

        if self.fast_recovery == Some(hole) {
            return None;
        }

        let later_acked = self
            .in_flight
            .iter()
            .map(|(tx_seq, _)| tx_seq)
            .filter(|tx_seq| tx_seq.serial_gt(hole) && Self::ack_covers(ack, *tx_seq))
            .count();

        (later_acked >= threshold as usize).then_some(hole)
    }

    pub fn schedule_fast_retransmit(&mut self, tx_seq: StreamSeq, now: Instant) {
        if let Some(in_flight) = self.in_flight.get_mut(&tx_seq) {
            in_flight.retry_at = Some(now);
            self.fast_recovery = Some(tx_seq);
        }
    }

    pub fn set_retry_deadline(&mut self, tx_seq: StreamSeq, retry_at: Instant) {
        if let Some(in_flight) = self.in_flight.get_mut(&tx_seq) {
            in_flight.retry_at = Some(retry_at);
        }
    }

    pub fn clear_fast_recovery(&mut self, ack_base: StreamSeq) {
        let should_clear = self.fast_recovery.is_some_and(|tx_seq| {
            tx_seq.serial_lte(ack_base) || !self.in_flight.contains_key(&tx_seq)
        });
        if should_clear {
            self.fast_recovery = None;
        }
    }

    pub fn remove_in_flight(&mut self, tx_seq: StreamSeq) -> Option<InFlightFrame> {
        let removed = self.in_flight.remove(&tx_seq);
        self.in_flight.advance_empty_front_until(self.next_tx_seq);
        if self.fast_recovery == Some(tx_seq) {
            self.fast_recovery = None;
        }
        removed
    }

    pub fn clear_transient_buffers(&mut self) {
        self.pending.clear();
        self.in_flight.clear_with_base(self.next_tx_seq);
        self.recv_buffer
            .clear_with_base(self.committed_rx_seq().next());
        self.clear_ack_schedule();
        self.fast_recovery = None;
    }

    pub fn ack_covers(ack: StreamAck, tx_seq: StreamSeq) -> bool {
        if tx_seq.serial_lte(ack.base) {
            return true;
        }
        let Some(delta) = ack.base.forward_distance_to(tx_seq) else {
            return false;
        };
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
                    && state.request.is_closed()
                    && state.response.closed
            }
            Self::Responder(state) => match &state.response {
                ResponderResponse::Accepted { body } => state.request.closed && body.is_closed(),
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
