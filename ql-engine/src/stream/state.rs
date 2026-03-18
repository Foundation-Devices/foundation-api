use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use super::{
    ring::SeqRing, StreamLocalRole, STREAM_ACK_EAGER_THRESHOLD, STREAM_WINDOW_CAPACITY,
    STREAM_WINDOW_SIZE,
};
use crate::{
    wire::{
        stream::{StreamAck, StreamFrame},
        StreamSeq,
    },
    StreamId,
};

#[derive(Debug, Default)]
pub struct StreamStore {
    streams: HashMap<StreamId, StreamState>,
    order: Vec<StreamId>,
    cursor: usize,
}

impl StreamStore {
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

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn id_at_offset(&self, offset: usize) -> Option<StreamId> {
        let len = self.order.len();
        if len == 0 || offset >= len {
            return None;
        }
        Some(self.order[(self.cursor + offset) % len])
    }

    pub fn ordered_id(&self, index: usize) -> Option<StreamId> {
        self.order.get(index).copied()
    }

    pub fn first_id(&self) -> Option<StreamId> {
        self.order.first().copied()
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
}

#[derive(Debug)]
pub struct StreamState {
    pub control: StreamControl,
    pub role: StreamRole,
}

impl StreamState {
    pub fn outbound_mut(&mut self, side: StreamSide) -> Option<&mut OutboundPhase> {
        match &mut self.role {
            StreamRole::Initiator(state) if side == StreamSide::Request => Some(&mut state.request),
            StreamRole::Responder(state) if side == StreamSide::Response => {
                Some(&mut state.response)
            }
            StreamRole::Initiator(_) | StreamRole::Responder(_) => None,
        }
    }

    pub fn inbound_mut(&mut self, side: StreamSide) -> Option<&mut InboundState> {
        match &mut self.role {
            StreamRole::Initiator(state) if side == StreamSide::Response => {
                Some(&mut state.response)
            }
            StreamRole::Responder(state) if side == StreamSide::Request => Some(&mut state.request),
            StreamRole::Initiator(_) | StreamRole::Responder(_) => None,
        }
    }

    pub fn outbound_side(&self) -> Option<StreamSide> {
        match self.role {
            StreamRole::Initiator(_) => Some(StreamSide::Request),
            StreamRole::Responder(_) => Some(StreamSide::Response),
        }
    }

    pub fn inbound_side(&self) -> Option<StreamSide> {
        match self.role {
            StreamRole::Initiator(_) => Some(StreamSide::Response),
            StreamRole::Responder(_) => Some(StreamSide::Request),
        }
    }

    pub fn awaiting_open(&self) -> bool {
        matches!(
            self.role,
            StreamRole::Responder(ResponderStream { opened: false, .. })
        )
    }

    pub fn can_reap(&self) -> bool {
        if !self.control.pending.is_empty()
            || !self.control.in_flight.is_empty()
            || !self.control.recv_buffer.is_empty()
            || !matches!(self.control.ack_state, AckState::Idle)
        {
            return false;
        }

        match self.role {
            StreamRole::Initiator(state) => state.request.is_closed() && state.response.closed,
            StreamRole::Responder(state) => state.request.closed && state.response.is_closed(),
        }
    }

    pub fn local_role(&self) -> StreamLocalRole {
        match self.role {
            StreamRole::Initiator(_) => StreamLocalRole::Initiator,
            StreamRole::Responder(_) => StreamLocalRole::Responder,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSide {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundPhase {
    Ready,
    FinPending,
    FinQueued,
    Closed,
}

impl OutboundPhase {
    pub fn from_prefix(fin: bool) -> Self {
        if fin {
            Self::FinQueued
        } else {
            Self::Ready
        }
    }

    pub fn is_closed(self) -> bool {
        self == Self::Closed
    }

    pub fn can_queue_data(self) -> bool {
        self == Self::Ready
    }

    pub fn finish(&mut self) {
        *self = match *self {
            Self::Ready | Self::FinPending => Self::FinPending,
            Self::FinQueued => Self::FinQueued,
            Self::Closed => Self::Closed,
        };
    }

    pub fn queue_fin(&mut self) -> bool {
        if *self != Self::FinPending {
            return false;
        }
        *self = Self::FinQueued;
        true
    }

    pub fn close(&mut self) -> bool {
        if *self == Self::Closed {
            return false;
        }
        *self = Self::Closed;
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    Ready,
    Issued { issue_id: u64 },
    WaitingRetry { retry_at: Instant },
}

#[derive(Debug)]
pub struct InFlightFrame {
    pub tx_seq: StreamSeq,
    pub frame: StreamFrame,
    pub attempt: u8,
    pub write_state: InFlightWriteState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferIncomingResult {
    Duplicate,
    AlreadyBuffered,
    Buffered { out_of_order: bool },
    OutOfWindow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckState {
    Idle,
    Delayed { due_at: Instant },
    Immediate,
}

#[derive(Debug)]
pub struct StreamControl {
    pub pending: VecDeque<StreamFrame>,
    pub in_flight: SeqRing<STREAM_WINDOW_CAPACITY, InFlightFrame>,
    pub next_tx_seq: StreamSeq,
    pub recv_buffer: SeqRing<STREAM_WINDOW_CAPACITY, StreamFrame>,
    pub ack_state: AckState,
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
            ack_state: AckState::Idle,
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

    pub fn note_ack(&mut self, now: Instant, ack_delay: Duration, immediate: bool) {
        self.ack_state = match self.ack_state {
            AckState::Immediate => AckState::Immediate,
            AckState::Delayed { due_at } if !immediate && !ack_delay.is_zero() => {
                AckState::Delayed { due_at }
            }
            _ if immediate || ack_delay.is_zero() => AckState::Immediate,
            _ => AckState::Delayed {
                due_at: now + ack_delay,
            },
        };
    }

    pub fn clear_ack_schedule(&mut self) {
        self.ack_state = AckState::Idle;
    }

    pub fn maybe_force_ack_for_progress(&mut self) {
        if matches!(self.ack_state, AckState::Idle) {
            return;
        }
        let committed = self.committed_rx_seq();
        let progressed = self
            .last_sent_ack_base
            .forward_distance_to(committed)
            .unwrap_or(0);
        if progressed >= STREAM_ACK_EAGER_THRESHOLD {
            self.ack_state = AckState::Immediate;
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

    pub fn take_piggyback_ack(&mut self, inbound_alive: bool) -> StreamAck {
        if !inbound_alive || matches!(self.ack_state, AckState::Idle) {
            return StreamAck::EMPTY;
        }
        let ack = self.current_ack();
        self.clear_ack_schedule();
        self.note_ack_sent(ack);
        ack
    }

    pub fn ack_deadline(&self) -> Option<Instant> {
        match self.ack_state {
            AckState::Delayed { due_at } => Some(due_at),
            AckState::Idle | AckState::Immediate => None,
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

    pub fn mark_write_issued(&mut self, tx_seq: StreamSeq, issue_id: u64) -> Option<StreamFrame> {
        let in_flight = self.in_flight.get_mut(&tx_seq)?;
        match in_flight.write_state {
            InFlightWriteState::Issued { .. } => return None,
            InFlightWriteState::WaitingRetry { .. } => {
                in_flight.attempt = in_flight.attempt.saturating_add(1);
            }
            InFlightWriteState::Ready => {}
        }
        in_flight.write_state = InFlightWriteState::Issued { issue_id };
        Some(in_flight.frame.clone())
    }

    pub fn frame_write_is_issued(&self, tx_seq: StreamSeq, issue_id: u64) -> bool {
        matches!(
            self.in_flight.get(&tx_seq).map(|in_flight| in_flight.write_state),
            Some(InFlightWriteState::Issued {
                issue_id: current_issue_id,
            }) if current_issue_id == issue_id
        )
    }

    pub fn complete_write(&mut self, tx_seq: StreamSeq, issue_id: u64, retry_at: Instant) -> bool {
        let Some(in_flight) = self.in_flight.get_mut(&tx_seq) else {
            return false;
        };
        match in_flight.write_state {
            InFlightWriteState::Issued {
                issue_id: current_issue_id,
            } if current_issue_id == issue_id => {
                in_flight.write_state = InFlightWriteState::WaitingRetry { retry_at };
                true
            }
            InFlightWriteState::Ready
            | InFlightWriteState::WaitingRetry { .. }
            | InFlightWriteState::Issued { .. } => false,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRole {
    Initiator(InitiatorStream),
    Responder(ResponderStream),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitiatorStream {
    pub request: OutboundPhase,
    pub response: InboundState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponderStream {
    pub opened: bool,
    pub request: InboundState,
    pub response: OutboundPhase,
    pub response_started: bool,
}
