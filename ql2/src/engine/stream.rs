use std::{
    collections::{HashMap, VecDeque},
    time::Instant,
};

use super::{ring::SeqRing, Token};
use crate::{
    wire::{
        stream::{CloseCode, CloseTarget, StreamAck, StreamFrame, StreamFrameClose},
        StreamSeq,
    },
    StreamId,
};

// todo: need to figure out protocol behavior for: if the peer ACKs your Open and then stays silent forever, the stream will stay pending forever

pub const STREAM_WINDOW_CAPACITY: usize = 8;
pub const STREAM_WINDOW_SIZE: u32 = STREAM_WINDOW_CAPACITY as u32;
pub const STREAM_ACK_EAGER_THRESHOLD: u32 = STREAM_WINDOW_SIZE / 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSide {
    Request,
    Response,
}

#[derive(Debug)]
pub struct StreamMeta {
    pub stream_id: StreamId,
    pub last_activity: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundPhase {
    Ready,
    FinPending,
    FinQueued,
    Closed,
}

#[derive(Debug)]
pub struct OutboundState {
    pub phase: OutboundPhase,
}

impl OutboundState {
    pub fn from_prefix(fin: bool) -> Self {
        Self {
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

    pub fn can_queue_data(&self) -> bool {
        self.phase == OutboundPhase::Ready
    }

    pub fn finish(&mut self) {
        self.phase = match self.phase {
            OutboundPhase::Ready | OutboundPhase::FinPending => OutboundPhase::FinPending,
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

    pub fn close(&mut self) -> bool {
        if self.phase == OutboundPhase::Closed {
            return false;
        }
        self.phase = OutboundPhase::Closed;
        true
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

    pub fn close(&mut self) -> bool {
        if self.closed {
            return false;
        }
        self.closed = true;
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InFlightWriteState {
    /// The frame has never been handed out to be written.
    Ready,
    /// The frame was handed out and is awaiting `complete_write`.
    Issued,
    /// The frame write completed and is waiting for retransmit eligibility.
    WaitingRetry { retry_at: Instant },
}

#[derive(Debug)]
pub struct InFlightFrame {
    pub tx_seq: StreamSeq,
    pub frame: StreamFrame,
    pub attempt: u8,
    pub write_state: InFlightWriteState,
}

#[derive(Debug)]
pub enum BufferIncomingResult {
    Duplicate,
    AlreadyBuffered,
    Buffered { out_of_order: bool },
    OutOfWindow,
}

// TODO: does it really make sense to have terminal control frames have sequence ids?
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

    pub fn take_piggyback_ack(&mut self, inbound_alive: bool) -> StreamAck {
        if !inbound_alive || !self.ack_dirty {
            return StreamAck::EMPTY;
        }
        let ack = self.current_ack();
        self.clear_ack_schedule();
        self.note_ack_sent(ack);
        ack
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
            in_flight.write_state = InFlightWriteState::WaitingRetry { retry_at: now };
            self.fast_recovery = Some(tx_seq);
        }
    }

    pub fn mark_write_issued(&mut self, tx_seq: StreamSeq) -> Option<StreamFrame> {
        let in_flight = self.in_flight.get_mut(&tx_seq)?;
        match in_flight.write_state {
            InFlightWriteState::Issued => return None,
            InFlightWriteState::WaitingRetry { .. } => {
                in_flight.attempt = in_flight.attempt.saturating_add(1);
            }
            InFlightWriteState::Ready => {}
        }
        in_flight.write_state = InFlightWriteState::Issued;
        Some(in_flight.frame.clone())
    }

    pub fn complete_write(&mut self, tx_seq: StreamSeq, retry_at: Instant) {
        if let Some(in_flight) = self.in_flight.get_mut(&tx_seq) {
            in_flight.write_state = InFlightWriteState::WaitingRetry { retry_at };
        }
    }

    pub fn set_retry_deadline(&mut self, tx_seq: StreamSeq, retry_at: Instant) {
        if let Some(in_flight) = self.in_flight.get_mut(&tx_seq) {
            in_flight.write_state = InFlightWriteState::WaitingRetry { retry_at };
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
        self.ack_outbound_token = None;
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
    pub request: OutboundState,
    pub response: InboundState,
}

#[derive(Debug)]
pub struct ResponderStream {
    pub request: InboundState,
    pub response: OutboundState,
    pub response_started: bool,
}

#[derive(Debug)]
pub struct ProvisionalStream {
    pub timeout_token: Token,
}

#[derive(Debug)]
pub enum StreamRole {
    Initiator(InitiatorStream),
    Responder(ResponderStream),
    Provisional(ProvisionalStream),
}

#[derive(Debug)]
pub struct StreamState {
    pub meta: StreamMeta,
    pub control: StreamControl,
    pub role: StreamRole,
}

impl StreamState {
    pub fn parts_mut(&mut self) -> (&mut StreamMeta, &mut StreamControl, &mut StreamRole) {
        (&mut self.meta, &mut self.control, &mut self.role)
    }

    pub fn outbound_mut(&mut self, side: StreamSide) -> Option<&mut OutboundState> {
        match &mut self.role {
            StreamRole::Initiator(state) if side == StreamSide::Request => Some(&mut state.request),
            StreamRole::Responder(state) if side == StreamSide::Response => {
                Some(&mut state.response)
            }
            _ => None,
        }
    }

    pub fn inbound_mut(&mut self, side: StreamSide) -> Option<&mut InboundState> {
        match &mut self.role {
            StreamRole::Initiator(state) if side == StreamSide::Response => {
                Some(&mut state.response)
            }
            StreamRole::Responder(state) if side == StreamSide::Request => Some(&mut state.request),
            _ => None,
        }
    }

    pub fn provisional_timeout_token(&self) -> Option<Token> {
        match &self.role {
            StreamRole::Provisional(state) => Some(state.timeout_token),
            _ => None,
        }
    }

    pub fn outbound_side(&self) -> Option<StreamSide> {
        match &self.role {
            StreamRole::Initiator(_) => Some(StreamSide::Request),
            StreamRole::Responder(_) => Some(StreamSide::Response),
            StreamRole::Provisional(_) => None,
        }
    }

    pub fn inbound_side(&self) -> Option<StreamSide> {
        match &self.role {
            StreamRole::Initiator(_) => Some(StreamSide::Response),
            StreamRole::Responder(_) => Some(StreamSide::Request),
            StreamRole::Provisional(_) => None,
        }
    }

    pub fn is_provisional(&self) -> bool {
        matches!(&self.role, StreamRole::Provisional(_))
    }

    pub fn can_reap(&self) -> bool {
        if !self.control.pending.is_empty()
            || !self.control.in_flight.is_empty()
            || !self.control.recv_buffer.is_empty()
            || self.control.ack_dirty
            || self.control.ack_outbound_token.is_some()
        {
            return false;
        }
        match &self.role {
            StreamRole::Initiator(state) => state.request.is_closed() && state.response.closed,
            StreamRole::Responder(state) => state.request.closed && state.response.is_closed(),
            StreamRole::Provisional(_) => false,
        }
    }
}

#[derive(Debug, Default)]
pub struct StreamStore {
    streams: HashMap<StreamId, StreamState>,
    order: Vec<StreamId>,
    cursor: usize,
}

impl StreamStore {
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    pub fn contains_key(&self, stream_id: &StreamId) -> bool {
        self.streams.contains_key(stream_id)
    }

    pub fn insert(&mut self, stream_id: StreamId, stream: StreamState) -> Option<StreamState> {
        if !self.streams.contains_key(&stream_id) {
            self.order.push(stream_id);
        }
        self.streams.insert(stream_id, stream)
    }

    pub fn get(&self, stream_id: &StreamId) -> Option<&StreamState> {
        self.streams.get(stream_id)
    }

    pub fn get_mut(&mut self, stream_id: &StreamId) -> Option<&mut StreamState> {
        self.streams.get_mut(stream_id)
    }

    pub fn remove(&mut self, stream_id: &StreamId) -> Option<StreamState> {
        let removed = self.streams.remove(stream_id);
        if removed.is_some() {
            if let Some(index) = self.order.iter().position(|id| id == stream_id) {
                self.order.remove(index);
                if self.order.is_empty() {
                    self.cursor = 0;
                } else if index < self.cursor {
                    self.cursor -= 1;
                } else if self.cursor >= self.order.len() {
                    self.cursor = 0;
                }
            }
        }
        removed
    }

    pub fn values(&self) -> impl Iterator<Item = &StreamState> {
        self.streams.values()
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut StreamState> {
        self.streams.values_mut()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&StreamId, &StreamState)> {
        self.streams.iter()
    }

    pub fn into_inner(self) -> HashMap<StreamId, StreamState> {
        self.streams
    }

    pub fn scan_from_cursor(&self) -> impl Iterator<Item = StreamId> + '_ {
        let len = self.order.len();
        (0..len).map(move |offset| self.order[(self.cursor + offset) % len])
    }

    pub fn advance_cursor_after(&mut self, stream_id: StreamId) {
        if let Some(index) = self.order.iter().position(|id| *id == stream_id) {
            self.cursor = if self.order.is_empty() {
                0
            } else {
                (index + 1) % self.order.len()
            };
        }
    }

    pub fn stream_retry_deadline(&self) -> Option<Instant> {
        self.streams
            .values()
            .flat_map(|stream| {
                stream
                    .control
                    .in_flight
                    .iter()
                    .filter_map(|(_, in_flight)| match in_flight.write_state {
                        InFlightWriteState::WaitingRetry { retry_at } => Some(retry_at),
                        InFlightWriteState::Ready | InFlightWriteState::Issued => None,
                    })
            })
            .min()
    }
}

pub fn close_frame(
    stream_id: StreamId,
    target: CloseTarget,
    code: CloseCode,
    payload: Vec<u8>,
) -> StreamFrame {
    StreamFrame::Close(StreamFrameClose {
        stream_id,
        target,
        code,
        payload,
    })
}
