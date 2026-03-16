use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use super::{
    ring::SeqRing, Outbound, OutboundCompletion, StreamCloseEvent, StreamCloseKind, StreamError,
    StreamEventSink, StreamFsm, StreamFsmConfig, StreamLocalRole, StreamNamespace, WriteError,
    STREAM_ACK_EAGER_THRESHOLD, STREAM_WINDOW_CAPACITY, STREAM_WINDOW_SIZE,
};
use crate::{
    wire::{
        stream::{
            BodyChunk, CloseCode, CloseTarget, StreamAck, StreamAckBody, StreamBody, StreamFrame,
            StreamFrameClose, StreamFrameData, StreamFrameOpen, StreamMessage,
        },
        StreamSeq,
    },
    StreamId,
};

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

#[derive(Debug)]
pub struct StreamControl {
    pub pending: VecDeque<StreamFrame>,
    pub in_flight: SeqRing<STREAM_WINDOW_CAPACITY, InFlightFrame>,
    pub next_tx_seq: StreamSeq,
    pub recv_buffer: SeqRing<STREAM_WINDOW_CAPACITY, StreamFrame>,
    pub ack_dirty: bool,
    pub ack_immediate: bool,
    pub ack_delay_deadline: Option<Instant>,
    pub ack_issue_id: Option<u64>,
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
            ack_delay_deadline: None,
            ack_issue_id: None,
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

    pub fn note_ack(&mut self, immediate: bool) {
        self.ack_dirty = true;
        self.ack_immediate |= immediate;
    }

    pub fn clear_ack_schedule(&mut self) {
        self.ack_dirty = false;
        self.ack_immediate = false;
        self.ack_delay_deadline = None;
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

    pub fn take_piggyback_ack(&mut self, inbound_alive: bool) -> StreamAck {
        if !inbound_alive || !self.ack_dirty {
            return StreamAck::EMPTY;
        }
        let ack = self.current_ack();
        self.clear_ack_schedule();
        self.note_ack_sent(ack);
        ack
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
        self.ack_issue_id = None;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRole {
    Initiator(InitiatorStream),
    Responder(ResponderStream),
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
            || self.control.ack_dirty
            || self.control.ack_issue_id.is_some()
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundSelection {
    Ack,
    InitialFrame { tx_seq: StreamSeq },
    RetryFrame { tx_seq: StreamSeq },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamDisposition {
    Keep,
    Remove,
    Reap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimerAction {
    None,
    Fail,
}

pub fn new(config: StreamFsmConfig) -> StreamFsm {
    StreamFsm {
        config,
        streams: StreamStore::default(),
        next_stream_id: 1,
        next_issue_id: 1,
    }
}

pub fn open_stream(
    stream_fsm: &mut StreamFsm,
    request_head: Vec<u8>,
    request_prefix: Option<BodyChunk>,
) -> StreamId {
    let stream_id = stream_fsm.next_stream_id();
    let request_prefix_fin = request_prefix.as_ref().is_some_and(|chunk| chunk.fin);
    let mut stream = StreamState {
        control: StreamControl {
            pending: VecDeque::from([StreamFrame::Open(StreamFrameOpen {
                stream_id,
                request_head,
                request_prefix,
            })]),
            ..Default::default()
        },
        role: StreamRole::Initiator(InitiatorStream {
            request: OutboundPhase::from_prefix(request_prefix_fin),
            response: InboundState::new(),
        }),
    };
    StreamFsm::drive_stream(&mut stream, stream_id);
    stream_fsm.streams.insert(stream_id, stream);
    stream_id
}

pub fn write_stream(
    stream_fsm: &mut StreamFsm,
    stream_id: StreamId,
    bytes: Vec<u8>,
) -> Result<(), StreamError> {
    if bytes.is_empty() {
        return Ok(());
    }

    let Some(stream) = stream_fsm.streams.get_mut(&stream_id) else {
        return Err(StreamError::MissingStream);
    };
    let Some(side) = stream.outbound_side() else {
        return Err(StreamError::NotWritable);
    };
    if let StreamRole::Responder(state) = &mut stream.role {
        if side == StreamSide::Response {
            state.response_started = true;
        }
    }
    let Some(outbound) = stream.outbound_mut(side) else {
        return Err(StreamError::NotWritable);
    };
    if !outbound.can_queue_data() {
        return Err(StreamError::NotWritable);
    }

    stream
        .control
        .pending
        .push_back(StreamFrame::Data(StreamFrameData {
            stream_id,
            chunk: BodyChunk { bytes, fin: false },
        }));
    StreamFsm::drive_stream(stream, stream_id);
    Ok(())
}

pub fn finish_stream(stream_fsm: &mut StreamFsm, stream_id: StreamId) -> Result<(), StreamError> {
    let Some(stream) = stream_fsm.streams.get_mut(&stream_id) else {
        return Err(StreamError::MissingStream);
    };
    let Some(side) = stream.outbound_side() else {
        return Err(StreamError::NotWritable);
    };
    if let StreamRole::Responder(state) = &mut stream.role {
        if side == StreamSide::Response {
            state.response_started = true;
        }
    }
    let Some(outbound) = stream.outbound_mut(side) else {
        return Err(StreamError::NotWritable);
    };
    outbound.finish();
    StreamFsm::drive_stream(stream, stream_id);
    Ok(())
}

pub fn close_stream(
    stream_fsm: &mut StreamFsm,
    stream_id: StreamId,
    target: CloseTarget,
    code: CloseCode,
    payload: Vec<u8>,
) -> Result<(), StreamError> {
    let Some(stream) = stream_fsm.streams.get_mut(&stream_id) else {
        return Err(StreamError::MissingStream);
    };

    let mut dirty = false;
    if matches!(target, CloseTarget::Request | CloseTarget::Both) {
        if let Some(inbound) = stream.inbound_mut(StreamSide::Request) {
            dirty |= inbound.close();
        }
        if let Some(outbound) = stream.outbound_mut(StreamSide::Request) {
            dirty |= outbound.close();
        }
    }
    if matches!(target, CloseTarget::Response | CloseTarget::Both) {
        if let Some(inbound) = stream.inbound_mut(StreamSide::Response) {
            dirty |= inbound.close();
        }
        if let Some(outbound) = stream.outbound_mut(StreamSide::Response) {
            dirty |= outbound.close();
        }
    }

    if dirty {
        stream
            .control
            .pending
            .push_front(close_frame(stream_id, target, code, payload));
        StreamFsm::drive_stream(stream, stream_id);
    }

    Ok(())
}

pub fn receive(
    stream_fsm: &mut StreamFsm,
    now: Instant,
    body: StreamBody,
    events: &mut impl StreamEventSink,
) {
    match body {
        StreamBody::Ack(StreamAckBody { stream_id, ack, .. }) => {
            stream_fsm.process_ack(now, stream_id, ack, events)
        }
        StreamBody::Message(StreamMessage {
            tx_seq, ack, frame, ..
        }) => {
            let stream_id = frame.stream_id();
            stream_fsm.process_ack(now, stream_id, ack, events);

            if !stream_fsm.streams.contains_key(&stream_id) {
                if !stream_fsm
                    .config
                    .local_namespace
                    .remote()
                    .matches(stream_id)
                {
                    return;
                }
                stream_fsm.streams.insert(
                    stream_id,
                    StreamState {
                        control: StreamControl::default(),
                        role: StreamRole::Responder(ResponderStream {
                            opened: false,
                            request: InboundState::new(),
                            response: OutboundPhase::Ready,
                            response_started: false,
                        }),
                    },
                );
            }

            let disposition = {
                let Some(stream) = stream_fsm.streams.get_mut(&stream_id) else {
                    return;
                };

                match stream.control.buffer_incoming(tx_seq, frame) {
                    BufferIncomingResult::OutOfWindow => {
                        if stream.awaiting_open() {
                            events.close(StreamCloseEvent {
                                kind: StreamCloseKind::Detached,
                                role: StreamLocalRole::Responder,
                                frame: StreamFrameClose {
                                    stream_id,
                                    target: CloseTarget::Both,
                                    code: CloseCode::PROTOCOL,
                                    payload: Vec::new(),
                                },
                            });
                            StreamDisposition::Remove
                        } else {
                            StreamFsm::queue_protocol_close(stream_id, stream, events);
                            StreamDisposition::Keep
                        }
                    }
                    BufferIncomingResult::Duplicate | BufferIncomingResult::AlreadyBuffered => {
                        stream.control.note_ack(true);
                        StreamFsm::schedule_stream_ack(
                            &mut stream.control,
                            now,
                            stream_fsm.config.ack_delay,
                        );
                        StreamDisposition::Keep
                    }
                    BufferIncomingResult::Buffered { out_of_order } => {
                        stream.control.note_ack(out_of_order);
                        StreamFsm::drain_committed_frames(
                            now,
                            stream_id,
                            stream,
                            stream_fsm.config.ack_delay,
                            events,
                        )
                    }
                }
            };

            match disposition {
                StreamDisposition::Keep => {}
                StreamDisposition::Remove => {
                    stream_fsm.streams.remove(&stream_id);
                }
                StreamDisposition::Reap => {
                    stream_fsm.streams.remove(&stream_id);
                    events.reaped(stream_id);
                }
            }
        }
    }
}

pub fn next_outbound(
    stream_fsm: &mut StreamFsm,
    now: Instant,
    valid_until: u64,
) -> Option<Outbound> {
    for offset in 0..stream_fsm.streams.len() {
        let stream_id = stream_fsm.streams.id_at_offset(offset)?;
        let selection = {
            let stream = stream_fsm.streams.get(&stream_id)?;
            stream_fsm.select_outbound(stream, now)
        };
        let Some(selection) = selection else {
            continue;
        };

        let issue_id = stream_fsm.next_issue_id();
        let outbound = match selection {
            OutboundSelection::Ack => {
                let stream = stream_fsm.streams.get_mut(&stream_id)?;
                let ack = stream.control.current_ack();
                stream.control.clear_ack_schedule();
                stream.control.note_ack_sent(ack);
                stream.control.ack_issue_id = Some(issue_id);
                Outbound {
                    body: StreamBody::Ack(StreamAckBody {
                        stream_id,
                        ack,
                        valid_until,
                    }),
                    completion: OutboundCompletion::Ack {
                        stream_id,
                        issue_id,
                    },
                }
            }
            OutboundSelection::InitialFrame { tx_seq }
            | OutboundSelection::RetryFrame { tx_seq } => {
                let stream = stream_fsm.streams.get_mut(&stream_id)?;
                let inbound_alive = match stream.role {
                    StreamRole::Initiator(state) => !state.response.closed,
                    StreamRole::Responder(state) => !state.request.closed,
                };
                let ack = stream.control.take_piggyback_ack(inbound_alive);
                let frame = stream.control.mark_write_issued(tx_seq, issue_id)?;
                Outbound {
                    body: StreamBody::Message(StreamMessage {
                        tx_seq,
                        ack,
                        valid_until,
                        frame,
                    }),
                    completion: OutboundCompletion::Frame {
                        stream_id,
                        tx_seq,
                        issue_id,
                    },
                }
            }
        };

        stream_fsm.streams.advance_cursor_after(stream_id);
        return Some(outbound);
    }

    None
}

pub fn complete_outbound(
    stream_fsm: &mut StreamFsm,
    now: Instant,
    completion: OutboundCompletion,
    result: Result<(), WriteError>,
    events: &mut impl StreamEventSink,
) {
    match completion {
        OutboundCompletion::Ack {
            stream_id,
            issue_id,
        } => {
            if let Some(stream) = stream_fsm.streams.get_mut(&stream_id) {
                if stream.control.ack_issue_id == Some(issue_id) {
                    stream.control.ack_issue_id = None;
                    if result.is_err() {
                        stream.control.note_ack(true);
                    }
                    if stream.can_reap() {
                        stream_fsm.streams.remove(&stream_id);
                        events.reaped(stream_id);
                    }
                }
            }
        }
        OutboundCompletion::Frame {
            stream_id,
            tx_seq,
            issue_id,
        } => match result {
            Ok(()) => {
                if let Some(stream) = stream_fsm.streams.get_mut(&stream_id) {
                    let _ = stream.control.complete_write(
                        tx_seq,
                        issue_id,
                        now + stream_fsm.config.ack_timeout,
                    );
                }
            }
            Err(WriteError::SendFailed) => {
                let should_fail = stream_fsm
                    .streams
                    .get(&stream_id)
                    .is_some_and(|stream| stream.control.frame_write_is_issued(tx_seq, issue_id));
                if should_fail {
                    stream_fsm.fail_stream_by_id(stream_id, StreamError::SendFailed, events);
                }
            }
        },
    }
}

pub fn on_timer(stream_fsm: &mut StreamFsm, now: Instant, events: &mut impl StreamEventSink) {
    let mut index = 0;
    while let Some(stream_id) = stream_fsm.streams.ordered_id(index) {
        let action = {
            let stream = stream_fsm
                .streams
                .get(&stream_id)
                .expect("ordered stream id should exist");
            if stream.control.in_flight.iter().any(|(_, in_flight)| {
                matches!(
                    in_flight.write_state,
                    InFlightWriteState::WaitingRetry { retry_at }
                        if retry_at <= now && in_flight.attempt >= stream_fsm.config.retry_limit
                )
            }) {
                TimerAction::Fail
            } else {
                TimerAction::None
            }
        };

        match action {
            TimerAction::Fail => {
                stream_fsm.fail_stream_by_id(stream_id, StreamError::Timeout, events);
            }
            TimerAction::None => {
                if let Some(stream) = stream_fsm.streams.get_mut(&stream_id) {
                    if stream
                        .control
                        .ack_delay_deadline
                        .is_some_and(|deadline| deadline <= now)
                    {
                        stream.control.ack_delay_deadline = None;
                        stream.control.ack_immediate = true;
                    }
                }
                index += 1;
            }
        }
    }
}

pub fn next_deadline(stream_fsm: &StreamFsm) -> Option<Instant> {
    let mut next = None;
    for stream in stream_fsm.streams.values() {
        if let Some(deadline) = stream.control.ack_delay_deadline {
            next = min_deadline(next, deadline);
        }
        for (_, in_flight) in stream.control.in_flight.iter() {
            if let InFlightWriteState::WaitingRetry { retry_at } = in_flight.write_state {
                next = min_deadline(next, retry_at);
            }
        }
    }
    next
}

pub fn abort(stream_fsm: &mut StreamFsm, error: StreamError, events: &mut impl StreamEventSink) {
    while let Some(stream_id) = stream_fsm.streams.first_id() {
        stream_fsm.fail_stream_by_id(stream_id, error.clone(), events);
    }
}

impl StreamFsm {
    pub(crate) fn next_stream_id(&mut self) -> StreamId {
        let seq = self.next_stream_id;
        self.next_stream_id = seq.wrapping_add(1);
        StreamId((seq & !StreamNamespace::BIT) | self.config.local_namespace.bit())
    }

    fn next_issue_id(&mut self) -> u64 {
        let id = self.next_issue_id;
        self.next_issue_id = id.wrapping_add(1);
        id
    }

    fn select_outbound(&self, stream: &StreamState, now: Instant) -> Option<OutboundSelection> {
        if let Some(tx_seq) = stream
            .control
            .in_flight
            .iter()
            .find_map(|(tx_seq, in_flight)| {
                matches!(
                    in_flight.write_state,
                    InFlightWriteState::WaitingRetry { retry_at }
                        if retry_at <= now && in_flight.attempt < self.config.retry_limit
                )
                .then_some(tx_seq)
            })
        {
            return Some(OutboundSelection::RetryFrame { tx_seq });
        }
        if let Some(tx_seq) = stream
            .control
            .in_flight
            .iter()
            .find_map(|(tx_seq, in_flight)| {
                matches!(in_flight.write_state, InFlightWriteState::Ready).then_some(tx_seq)
            })
        {
            return Some(OutboundSelection::InitialFrame { tx_seq });
        }

        (stream.control.ack_dirty
            && stream.control.ack_immediate
            && stream.control.ack_issue_id.is_none())
        .then_some(OutboundSelection::Ack)
    }

    fn process_ack(
        &mut self,
        now: Instant,
        stream_id: StreamId,
        ack: StreamAck,
        events: &mut impl StreamEventSink,
    ) {
        if ack == StreamAck::EMPTY {
            return;
        }

        let should_reap = {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return;
            };
            stream.control.clear_fast_recovery(ack.base);
            let fast_retransmit = stream
                .control
                .fast_retransmit_candidate(ack, self.config.fast_retransmit_threshold);

            loop {
                let acked_tx_seq =
                    stream
                        .control
                        .in_flight
                        .iter()
                        .find_map(|(tx_seq, in_flight)| match in_flight.write_state {
                            InFlightWriteState::Ready => None,
                            InFlightWriteState::Issued { .. }
                            | InFlightWriteState::WaitingRetry { .. } => {
                                StreamControl::ack_covers(ack, tx_seq).then_some(tx_seq)
                            }
                        });
                let Some(tx_seq) = acked_tx_seq else {
                    break;
                };
                let Some(in_flight) = stream.control.remove_in_flight(tx_seq) else {
                    continue;
                };

                match in_flight.frame {
                    StreamFrame::Open(StreamFrameOpen { request_prefix, .. }) => {
                        if let StreamRole::Initiator(state) = &mut stream.role {
                            if request_prefix.as_ref().is_some_and(|chunk| chunk.fin)
                                && state.request.close()
                            {
                                events.outbound_closed(stream_id);
                            }
                        }
                    }
                    StreamFrame::Data(StreamFrameData {
                        chunk: BodyChunk { fin: true, .. },
                        ..
                    }) => {
                        if let Some(side) = stream.outbound_side() {
                            if let Some(outbound) = stream.outbound_mut(side) {
                                if outbound.close() {
                                    events.outbound_closed(stream_id);
                                }
                            }
                        }
                    }
                    StreamFrame::Close(frame) => {
                        let mut changed = false;
                        for side in [StreamSide::Request, StreamSide::Response] {
                            let affects_outbound = matches!(
                                (frame.target, side),
                                (CloseTarget::Request, StreamSide::Request)
                                    | (CloseTarget::Response, StreamSide::Response)
                                    | (CloseTarget::Both, _)
                            );
                            if affects_outbound {
                                if let Some(outbound) = stream.outbound_mut(side) {
                                    if outbound.close() {
                                        changed = true;
                                    }
                                }
                            }
                        }
                        if changed {
                            events.close(StreamCloseEvent {
                                kind: StreamCloseKind::Acked,
                                role: stream.local_role(),
                                frame,
                            });
                        }
                    }
                    StreamFrame::Data(_) => {}
                }
            }

            if let Some(tx_seq) = fast_retransmit {
                stream.control.schedule_fast_retransmit(tx_seq, now);
            }
            Self::drive_stream(stream, stream_id);
            stream.can_reap()
        };

        if should_reap {
            self.streams.remove(&stream_id);
            events.reaped(stream_id);
        }
    }

    fn schedule_stream_ack(control: &mut StreamControl, now: Instant, ack_delay: Duration) {
        if !control.ack_dirty {
            return;
        }
        if control.ack_immediate || ack_delay.is_zero() {
            control.ack_delay_deadline = None;
            return;
        }
        if control.ack_delay_deadline.is_none() {
            control.ack_delay_deadline = Some(now + ack_delay);
        }
    }

    fn drain_committed_frames(
        now: Instant,
        stream_id: StreamId,
        stream: &mut StreamState,
        ack_delay: Duration,
        events: &mut impl StreamEventSink,
    ) -> StreamDisposition {
        loop {
            let Some((tx_seq, frame)) = stream.control.pop_next_committable() else {
                break;
            };

            if stream.awaiting_open()
                && (tx_seq != StreamSeq::START || !matches!(frame, StreamFrame::Open(_)))
            {
                return StreamDisposition::Remove;
            }

            match frame {
                StreamFrame::Open(frame) => {
                    Self::handle_stream_open(stream_id, stream, frame, events)
                }
                StreamFrame::Close(frame) => {
                    Self::handle_stream_close_from_peer(stream_id, stream, frame, events)
                }
                StreamFrame::Data(frame) => {
                    Self::handle_stream_data(stream_id, stream, frame, events)
                }
            }
        }

        stream.control.maybe_force_ack_for_progress();
        Self::schedule_stream_ack(&mut stream.control, now, ack_delay);
        if stream.can_reap() {
            StreamDisposition::Reap
        } else {
            StreamDisposition::Keep
        }
    }

    fn handle_stream_open(
        stream_id: StreamId,
        stream: &mut StreamState,
        frame: StreamFrameOpen,
        events: &mut impl StreamEventSink,
    ) {
        let StreamFrameOpen {
            request_head,
            request_prefix,
            ..
        } = frame;

        let StreamRole::Responder(state) = &mut stream.role else {
            Self::queue_protocol_close(stream_id, stream, events);
            return;
        };
        if state.opened {
            Self::queue_protocol_close(stream_id, stream, events);
            return;
        }

        let request_fin = request_prefix.as_ref().is_some_and(|chunk| chunk.fin);
        state.opened = true;
        if request_fin {
            let _ = stream
                .inbound_mut(StreamSide::Request)
                .expect("responder request side should exist")
                .close();
        }
        events.opened(stream_id, request_head, request_prefix);
    }

    fn handle_stream_close_from_peer(
        stream_id: StreamId,
        stream: &mut StreamState,
        frame: StreamFrameClose,
        events: &mut impl StreamEventSink,
    ) {
        let StreamFrameClose {
            target,
            code,
            payload,
            ..
        } = frame;
        Self::apply_remote_close(stream_id, stream, target, code, payload, events);
    }

    fn handle_stream_data(
        stream_id: StreamId,
        stream: &mut StreamState,
        frame: StreamFrameData,
        events: &mut impl StreamEventSink,
    ) {
        let Some(side) = stream.inbound_side() else {
            Self::queue_protocol_close(stream_id, stream, events);
            return;
        };
        let Some(inbound) = stream.inbound_mut(side) else {
            Self::queue_protocol_close(stream_id, stream, events);
            return;
        };
        if inbound.closed {
            Self::queue_protocol_close(stream_id, stream, events);
            return;
        }

        let BodyChunk { bytes, fin } = frame.chunk;
        if !bytes.is_empty() {
            events.inbound_data(stream_id, bytes);
        }
        if fin && inbound.close() {
            events.inbound_finished(stream_id);
        }
    }

    fn drive_stream(stream: &mut StreamState, stream_id: StreamId) {
        match &mut stream.role {
            StreamRole::Initiator(state) => Self::drive_stream_outbound(
                stream_id,
                &mut stream.control,
                Some(&mut state.request),
            ),
            StreamRole::Responder(state) => Self::drive_stream_outbound(
                stream_id,
                &mut stream.control,
                Some(&mut state.response),
            ),
        }
    }

    fn drive_stream_outbound(
        stream_id: StreamId,
        control: &mut StreamControl,
        mut outbound: Option<&mut OutboundPhase>,
    ) {
        loop {
            if control.send_window_has_space() {
                if let Some(frame) = control.pending.pop_front() {
                    let tx_seq = control.take_tx_seq();
                    control.insert_in_flight(InFlightFrame {
                        tx_seq,
                        frame,
                        attempt: 0,
                        write_state: InFlightWriteState::Ready,
                    });
                    continue;
                }
            }
            if !control.send_window_has_space() {
                return;
            }
            let Some(outbound) = outbound.as_deref_mut() else {
                return;
            };
            if outbound.queue_fin() {
                let tx_seq = control.take_tx_seq();
                control.insert_in_flight(InFlightFrame {
                    tx_seq,
                    frame: StreamFrame::Data(StreamFrameData {
                        stream_id,
                        chunk: BodyChunk {
                            bytes: Vec::new(),
                            fin: true,
                        },
                    }),
                    attempt: 0,
                    write_state: InFlightWriteState::Ready,
                });
                continue;
            }
            return;
        }
    }

    fn queue_protocol_close(
        stream_id: StreamId,
        stream: &mut StreamState,
        events: &mut impl StreamEventSink,
    ) {
        stream.control.clear_transient_buffers();
        stream.control.pending.push_front(close_frame(
            stream_id,
            CloseTarget::Both,
            CloseCode::PROTOCOL,
            Vec::new(),
        ));
        for side in [StreamSide::Request, StreamSide::Response] {
            if let Some(outbound) = stream.outbound_mut(side) {
                if outbound.close() {
                    events.outbound_failed(stream_id, StreamError::StreamProtocol);
                }
            }
            if let Some(inbound) = stream.inbound_mut(side) {
                if inbound.close() {
                    events.inbound_failed(stream_id, StreamError::StreamProtocol);
                }
            }
        }
        Self::drive_stream(stream, stream_id);
    }

    fn apply_remote_close(
        stream_id: StreamId,
        stream: &mut StreamState,
        target: CloseTarget,
        code: CloseCode,
        payload: Vec<u8>,
        events: &mut impl StreamEventSink,
    ) {
        let frame = StreamFrameClose {
            stream_id,
            target,
            code,
            payload,
        };
        let mut changed = false;
        if matches!(target, CloseTarget::Request | CloseTarget::Both) {
            if let Some(inbound) = stream.inbound_mut(StreamSide::Request) {
                if inbound.close() {
                    changed = true;
                }
            }
            if let Some(outbound) = stream.outbound_mut(StreamSide::Request) {
                if outbound.close() {
                    changed = true;
                }
            }
        }
        if matches!(target, CloseTarget::Response | CloseTarget::Both) {
            if let Some(inbound) = stream.inbound_mut(StreamSide::Response) {
                if inbound.close() {
                    changed = true;
                }
            }
            if let Some(outbound) = stream.outbound_mut(StreamSide::Response) {
                if outbound.close() {
                    changed = true;
                }
            }
        }
        if changed {
            events.close(StreamCloseEvent {
                kind: StreamCloseKind::Remote,
                role: stream.local_role(),
                frame,
            });
        }
    }

    fn fail_stream_by_id(
        &mut self,
        stream_id: StreamId,
        error: StreamError,
        events: &mut impl StreamEventSink,
    ) {
        let Some(stream) = self.streams.remove(&stream_id) else {
            return;
        };

        match stream.role {
            StreamRole::Initiator(_) => {
                events.outbound_failed(stream_id, error.clone());
                events.inbound_failed(stream_id, error);
            }
            StreamRole::Responder(stream) => {
                if !stream.opened {
                    events.reaped(stream_id);
                    return;
                }
                events.inbound_failed(stream_id, error.clone());
                if stream.response_started || stream.response.is_closed() {
                    events.outbound_failed(stream_id, error);
                }
            }
        }
        events.reaped(stream_id);
    }
}

fn min_deadline(current: Option<Instant>, candidate: Instant) -> Option<Instant> {
    Some(match current {
        Some(current) => current.min(candidate),
        None => candidate,
    })
}

fn close_frame(
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
