use std::{
    array,
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use thiserror::Error;

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

pub const STREAM_WINDOW_CAPACITY: usize = 8;
pub const STREAM_WINDOW_SIZE: u32 = STREAM_WINDOW_CAPACITY as u32;
pub const STREAM_ACK_EAGER_THRESHOLD: u32 = STREAM_WINDOW_SIZE / 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamNamespace {
    Low,
    High,
}

impl StreamNamespace {
    const BIT: u32 = 1 << 31;

    pub fn bit(self) -> u32 {
        match self {
            Self::Low => 0,
            Self::High => Self::BIT,
        }
    }

    pub fn matches(self, stream_id: StreamId) -> bool {
        (stream_id.0 & Self::BIT) == self.bit()
    }

    pub fn remote(self) -> Self {
        match self {
            Self::Low => Self::High,
            Self::High => Self::Low,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MuxConfig {
    pub local_namespace: StreamNamespace,
    pub ack_delay: Duration,
    pub ack_timeout: Duration,
    pub fast_retransmit_threshold: u8,
    pub retry_limit: u8,
    pub provisional_timeout: Duration,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            local_namespace: StreamNamespace::Low,
            ack_delay: Duration::from_millis(5),
            ack_timeout: Duration::from_millis(150),
            fast_retransmit_threshold: 2,
            retry_limit: 5,
            provisional_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutboundCompletion {
    Ack {
        stream_id: StreamId,
        issue_id: u64,
    },
    Frame {
        stream_id: StreamId,
        tx_seq: StreamSeq,
        issue_id: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    pub body: StreamBody,
    pub completion: OutboundCompletion,
}

pub trait MuxEventSink {
    fn opened(
        &mut self,
        stream_id: StreamId,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
    );

    fn inbound_data(&mut self, stream_id: StreamId, bytes: Vec<u8>);

    fn inbound_finished(&mut self, stream_id: StreamId);

    fn inbound_failed(&mut self, stream_id: StreamId, error: MuxError);

    fn close(&mut self, frame: StreamFrameClose);

    fn outbound_closed(&mut self, stream_id: StreamId);

    fn outbound_failed(&mut self, stream_id: StreamId, error: MuxError);

    fn reaped(&mut self, stream_id: StreamId);
}

impl MuxEventSink for () {
    fn opened(
        &mut self,
        _stream_id: StreamId,
        _request_head: Vec<u8>,
        _request_prefix: Option<BodyChunk>,
    ) {
    }

    fn inbound_data(&mut self, _stream_id: StreamId, _bytes: Vec<u8>) {}

    fn inbound_finished(&mut self, _stream_id: StreamId) {}

    fn inbound_failed(&mut self, _stream_id: StreamId, _error: MuxError) {}

    fn close(&mut self, _frame: StreamFrameClose) {}

    fn outbound_closed(&mut self, _stream_id: StreamId) {}

    fn outbound_failed(&mut self, _stream_id: StreamId, _error: MuxError) {}

    fn reaped(&mut self, _stream_id: StreamId) {}
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MuxError {
    #[error("missing stream")]
    MissingStream,
    #[error("stream is not writable")]
    NotWritable,
    #[error("send failed")]
    SendFailed,
    #[error("timeout")]
    Timeout,
    #[error("cancelled")]
    Cancelled,
    #[error("stream protocol error")]
    StreamProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WriteError {
    #[error("send failed")]
    SendFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamSide {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundPhase {
    Ready,
    FinPending,
    FinQueued,
    Closed,
}

impl OutboundPhase {
    fn from_prefix(fin: bool) -> Self {
        if fin {
            Self::FinQueued
        } else {
            Self::Ready
        }
    }

    fn is_closed(self) -> bool {
        self == Self::Closed
    }

    fn can_queue_data(self) -> bool {
        self == Self::Ready
    }

    fn finish(&mut self) {
        *self = match *self {
            Self::Ready | Self::FinPending => Self::FinPending,
            Self::FinQueued => Self::FinQueued,
            Self::Closed => Self::Closed,
        };
    }

    fn queue_fin(&mut self) -> bool {
        if *self != Self::FinPending {
            return false;
        }
        *self = Self::FinQueued;
        true
    }

    fn close(&mut self) -> bool {
        if *self == Self::Closed {
            return false;
        }
        *self = Self::Closed;
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InboundState {
    closed: bool,
}

impl InboundState {
    fn new() -> Self {
        Self { closed: false }
    }

    fn close(&mut self) -> bool {
        if self.closed {
            return false;
        }
        self.closed = true;
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InFlightWriteState {
    Ready,
    Issued { issue_id: u64 },
    WaitingRetry { retry_at: Instant },
}

#[derive(Debug)]
struct InFlightFrame {
    tx_seq: StreamSeq,
    frame: StreamFrame,
    attempt: u8,
    write_state: InFlightWriteState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BufferIncomingResult {
    Duplicate,
    AlreadyBuffered,
    Buffered { out_of_order: bool },
    OutOfWindow,
}

#[derive(Debug)]
struct StreamControl {
    pending: VecDeque<StreamFrame>,
    in_flight: SeqRing<STREAM_WINDOW_CAPACITY, InFlightFrame>,
    next_tx_seq: StreamSeq,
    recv_buffer: SeqRing<STREAM_WINDOW_CAPACITY, StreamFrame>,
    ack_dirty: bool,
    ack_immediate: bool,
    ack_delay_deadline: Option<Instant>,
    ack_issue_id: Option<u64>,
    last_sent_ack_base: StreamSeq,
    fast_recovery: Option<StreamSeq>,
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
    fn take_tx_seq(&mut self) -> StreamSeq {
        let tx_seq = self.next_tx_seq;
        self.next_tx_seq = self.next_tx_seq.next();
        tx_seq
    }

    fn send_window_has_space(&self) -> bool {
        self.in_flight.accepts_seq(self.next_tx_seq)
    }

    fn committed_rx_seq(&self) -> StreamSeq {
        self.recv_buffer.base_seq().prev()
    }

    fn note_ack(&mut self, immediate: bool) {
        self.ack_dirty = true;
        self.ack_immediate |= immediate;
    }

    fn clear_ack_schedule(&mut self) {
        self.ack_dirty = false;
        self.ack_immediate = false;
        self.ack_delay_deadline = None;
    }

    fn maybe_force_ack_for_progress(&mut self) {
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

    fn note_ack_sent(&mut self, ack: StreamAck) {
        if ack.base.serial_gt(self.last_sent_ack_base) {
            self.last_sent_ack_base = ack.base;
        }
    }

    fn current_ack(&self) -> StreamAck {
        StreamAck {
            base: self.committed_rx_seq(),
            bitmap: self.recv_buffer.bitmap(),
        }
    }

    fn take_piggyback_ack(&mut self, inbound_alive: bool) -> StreamAck {
        if !inbound_alive || !self.ack_dirty {
            return StreamAck::EMPTY;
        }
        let ack = self.current_ack();
        self.clear_ack_schedule();
        self.note_ack_sent(ack);
        ack
    }

    fn buffer_incoming(&mut self, tx_seq: StreamSeq, frame: StreamFrame) -> BufferIncomingResult {
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

    fn pop_next_committable(&mut self) -> Option<(StreamSeq, StreamFrame)> {
        self.recv_buffer.take_front()
    }

    fn insert_in_flight(&mut self, frame: InFlightFrame) {
        let _ = self.in_flight.set(frame.tx_seq, frame);
    }

    fn fast_retransmit_candidate(&self, ack: StreamAck, threshold: u8) -> Option<StreamSeq> {
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

    fn schedule_fast_retransmit(&mut self, tx_seq: StreamSeq, now: Instant) {
        if let Some(in_flight) = self.in_flight.get_mut(&tx_seq) {
            in_flight.write_state = InFlightWriteState::WaitingRetry { retry_at: now };
            self.fast_recovery = Some(tx_seq);
        }
    }

    fn mark_write_issued(&mut self, tx_seq: StreamSeq, issue_id: u64) -> Option<StreamFrame> {
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

    fn frame_write_is_issued(&self, tx_seq: StreamSeq, issue_id: u64) -> bool {
        matches!(
            self.in_flight.get(&tx_seq).map(|in_flight| in_flight.write_state),
            Some(InFlightWriteState::Issued {
                issue_id: current_issue_id,
            }) if current_issue_id == issue_id
        )
    }

    fn complete_write(&mut self, tx_seq: StreamSeq, issue_id: u64, retry_at: Instant) -> bool {
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

    fn clear_fast_recovery(&mut self, ack_base: StreamSeq) {
        let should_clear = self.fast_recovery.is_some_and(|tx_seq| {
            tx_seq.serial_lte(ack_base) || !self.in_flight.contains_key(&tx_seq)
        });
        if should_clear {
            self.fast_recovery = None;
        }
    }

    fn remove_in_flight(&mut self, tx_seq: StreamSeq) -> Option<InFlightFrame> {
        let removed = self.in_flight.remove(&tx_seq);
        self.in_flight.advance_empty_front_until(self.next_tx_seq);
        if self.fast_recovery == Some(tx_seq) {
            self.fast_recovery = None;
        }
        removed
    }

    fn clear_transient_buffers(&mut self) {
        self.pending.clear();
        self.in_flight.clear_with_base(self.next_tx_seq);
        self.recv_buffer
            .clear_with_base(self.committed_rx_seq().next());
        self.clear_ack_schedule();
        self.ack_issue_id = None;
        self.fast_recovery = None;
    }

    fn ack_covers(ack: StreamAck, tx_seq: StreamSeq) -> bool {
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
struct InitiatorStream {
    request: OutboundPhase,
    response: InboundState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResponderStream {
    request: InboundState,
    response: OutboundPhase,
    response_started: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProvisionalStream {
    expires_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamRole {
    Initiator(InitiatorStream),
    Responder(ResponderStream),
    Provisional(ProvisionalStream),
}

#[derive(Debug)]
struct StreamState {
    control: StreamControl,
    role: StreamRole,
}

impl StreamState {
    fn outbound_mut(&mut self, side: StreamSide) -> Option<&mut OutboundPhase> {
        match &mut self.role {
            StreamRole::Initiator(state) if side == StreamSide::Request => Some(&mut state.request),
            StreamRole::Responder(state) if side == StreamSide::Response => {
                Some(&mut state.response)
            }
            _ => None,
        }
    }

    fn inbound_mut(&mut self, side: StreamSide) -> Option<&mut InboundState> {
        match &mut self.role {
            StreamRole::Initiator(state) if side == StreamSide::Response => {
                Some(&mut state.response)
            }
            StreamRole::Responder(state) if side == StreamSide::Request => Some(&mut state.request),
            _ => None,
        }
    }

    fn outbound_side(&self) -> Option<StreamSide> {
        match self.role {
            StreamRole::Initiator(_) => Some(StreamSide::Request),
            StreamRole::Responder(_) => Some(StreamSide::Response),
            StreamRole::Provisional(_) => None,
        }
    }

    fn inbound_side(&self) -> Option<StreamSide> {
        match self.role {
            StreamRole::Initiator(_) => Some(StreamSide::Response),
            StreamRole::Responder(_) => Some(StreamSide::Request),
            StreamRole::Provisional(_) => None,
        }
    }

    fn is_provisional(&self) -> bool {
        matches!(self.role, StreamRole::Provisional(_))
    }

    fn provisional_deadline(&self) -> Option<Instant> {
        match self.role {
            StreamRole::Provisional(state) => Some(state.expires_at),
            _ => None,
        }
    }

    fn can_reap(&self) -> bool {
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
            StreamRole::Provisional(_) => false,
        }
    }
}

#[derive(Debug, Default)]
struct StreamStore {
    streams: HashMap<StreamId, StreamState>,
    order: Vec<StreamId>,
    cursor: usize,
}

impl StreamStore {
    fn contains_key(&self, stream_id: &StreamId) -> bool {
        self.streams.contains_key(stream_id)
    }

    fn insert(&mut self, stream_id: StreamId, stream: StreamState) -> Option<StreamState> {
        if !self.streams.contains_key(&stream_id) {
            self.order.push(stream_id);
        }
        self.streams.insert(stream_id, stream)
    }

    fn get(&self, stream_id: &StreamId) -> Option<&StreamState> {
        self.streams.get(stream_id)
    }

    fn get_mut(&mut self, stream_id: &StreamId) -> Option<&mut StreamState> {
        self.streams.get_mut(stream_id)
    }

    fn remove(&mut self, stream_id: &StreamId) -> Option<StreamState> {
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

    fn values(&self) -> impl Iterator<Item = &StreamState> {
        self.streams.values()
    }

    fn len(&self) -> usize {
        self.order.len()
    }

    fn id_at_offset(&self, offset: usize) -> Option<StreamId> {
        let len = self.order.len();
        if len == 0 || offset >= len {
            return None;
        }
        Some(self.order[(self.cursor + offset) % len])
    }

    fn ordered_id(&self, index: usize) -> Option<StreamId> {
        self.order.get(index).copied()
    }

    fn first_id(&self) -> Option<StreamId> {
        self.order.first().copied()
    }

    fn advance_cursor_after(&mut self, stream_id: StreamId) {
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

pub struct Mux {
    config: MuxConfig,
    streams: StreamStore,
    next_stream_id: u32,
    next_issue_id: u64,
}

impl Mux {
    pub fn new(config: MuxConfig) -> Self {
        Self {
            config,
            streams: StreamStore::default(),
            next_stream_id: 1,
            next_issue_id: 1,
        }
    }

    pub fn open_stream(
        &mut self,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
    ) -> StreamId {
        let stream_id = self.next_stream_id();
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
        Self::drive_stream(&mut stream, stream_id);
        self.streams.insert(stream_id, stream);
        stream_id
    }

    pub fn write_stream(&mut self, stream_id: StreamId, bytes: Vec<u8>) -> Result<(), MuxError> {
        if bytes.is_empty() {
            return Ok(());
        }

        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Err(MuxError::MissingStream);
        };
        let Some(side) = stream.outbound_side() else {
            return Err(MuxError::NotWritable);
        };
        if let StreamRole::Responder(state) = &mut stream.role {
            if side == StreamSide::Response {
                state.response_started = true;
            }
        }
        let Some(outbound) = stream.outbound_mut(side) else {
            return Err(MuxError::NotWritable);
        };
        if !outbound.can_queue_data() {
            return Err(MuxError::NotWritable);
        }

        stream
            .control
            .pending
            .push_back(StreamFrame::Data(StreamFrameData {
                stream_id,
                chunk: BodyChunk { bytes, fin: false },
            }));
        Self::drive_stream(stream, stream_id);
        Ok(())
    }

    pub fn finish_stream(&mut self, stream_id: StreamId) -> Result<(), MuxError> {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Err(MuxError::MissingStream);
        };
        let Some(side) = stream.outbound_side() else {
            return Err(MuxError::NotWritable);
        };
        if let StreamRole::Responder(state) = &mut stream.role {
            if side == StreamSide::Response {
                state.response_started = true;
            }
        }
        let Some(outbound) = stream.outbound_mut(side) else {
            return Err(MuxError::NotWritable);
        };
        outbound.finish();
        Self::drive_stream(stream, stream_id);
        Ok(())
    }

    pub fn close_stream(
        &mut self,
        stream_id: StreamId,
        target: CloseTarget,
        code: CloseCode,
        payload: Vec<u8>,
    ) -> Result<(), MuxError> {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Err(MuxError::MissingStream);
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
            Self::drive_stream(stream, stream_id);
        }

        Ok(())
    }

    pub fn receive(&mut self, now: Instant, body: StreamBody, events: &mut impl MuxEventSink) {
        match body {
            StreamBody::Ack(StreamAckBody { stream_id, ack, .. }) => {
                self.process_ack(now, stream_id, ack, events)
            }
            StreamBody::Message(StreamMessage {
                tx_seq, ack, frame, ..
            }) => {
                let stream_id = frame.stream_id();
                self.process_ack(now, stream_id, ack, events);

                if !self.streams.contains_key(&stream_id) {
                    if !self.config.local_namespace.remote().matches(stream_id) {
                        return;
                    }
                    self.streams.insert(
                        stream_id,
                        StreamState {
                            control: StreamControl::default(),
                            role: StreamRole::Provisional(ProvisionalStream {
                                expires_at: now + self.config.provisional_timeout,
                            }),
                        },
                    );
                }

                let disposition = {
                    let Some(stream) = self.streams.get_mut(&stream_id) else {
                        return;
                    };

                    match stream.control.buffer_incoming(tx_seq, frame) {
                        BufferIncomingResult::OutOfWindow => {
                            if stream.is_provisional() {
                                events.close(StreamFrameClose {
                                    stream_id,
                                    target: CloseTarget::Both,
                                    code: CloseCode::PROTOCOL,
                                    payload: Vec::new(),
                                });
                                StreamDisposition::Remove
                            } else {
                                Self::queue_protocol_close(stream_id, stream, events);
                                StreamDisposition::Keep
                            }
                        }
                        BufferIncomingResult::Duplicate | BufferIncomingResult::AlreadyBuffered => {
                            stream.control.note_ack(true);
                            Self::schedule_stream_ack(
                                &mut stream.control,
                                now,
                                self.config.ack_delay,
                            );
                            StreamDisposition::Keep
                        }
                        BufferIncomingResult::Buffered { out_of_order } => {
                            stream.control.note_ack(out_of_order);
                            Self::drain_committed_frames(
                                now,
                                stream_id,
                                stream,
                                self.config.ack_delay,
                                events,
                            )
                        }
                    }
                };

                match disposition {
                    StreamDisposition::Keep => {}
                    StreamDisposition::Remove => {
                        self.streams.remove(&stream_id);
                    }
                    StreamDisposition::Reap => {
                        self.streams.remove(&stream_id);
                        events.reaped(stream_id);
                    }
                }
            }
        }
    }

    pub fn next_outbound(&mut self, now: Instant, valid_until: u64) -> Option<Outbound> {
        for offset in 0..self.streams.len() {
            let stream_id = self.streams.id_at_offset(offset)?;
            let selection = {
                let stream = self.streams.get(&stream_id)?;
                self.select_outbound(stream, now)
            };
            let Some(selection) = selection else {
                continue;
            };

            let issue_id = self.next_issue_id();
            let outbound = match selection {
                OutboundSelection::Ack => {
                    let stream = self.streams.get_mut(&stream_id)?;
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
                    let stream = self.streams.get_mut(&stream_id)?;
                    let inbound_alive = match stream.role {
                        StreamRole::Initiator(state) => !state.response.closed,
                        StreamRole::Responder(state) => !state.request.closed,
                        StreamRole::Provisional(_) => continue,
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

            self.streams.advance_cursor_after(stream_id);
            return Some(outbound);
        }

        None
    }

    pub fn complete_outbound(
        &mut self,
        now: Instant,
        completion: OutboundCompletion,
        result: Result<(), WriteError>,
        events: &mut impl MuxEventSink,
    ) {
        match completion {
            OutboundCompletion::Ack {
                stream_id,
                issue_id,
            } => {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    if stream.control.ack_issue_id == Some(issue_id) {
                        stream.control.ack_issue_id = None;
                        if result.is_err() {
                            stream.control.note_ack(true);
                        }
                        if stream.can_reap() {
                            self.streams.remove(&stream_id);
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
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        let _ = stream.control.complete_write(
                            tx_seq,
                            issue_id,
                            now + self.config.ack_timeout,
                        );
                    }
                }
                Err(WriteError::SendFailed) => {
                    let should_fail = self.streams.get(&stream_id).is_some_and(|stream| {
                        stream.control.frame_write_is_issued(tx_seq, issue_id)
                    });
                    if should_fail {
                        self.fail_stream_by_id(stream_id, MuxError::SendFailed, events);
                    }
                }
            },
        }
    }

    pub fn on_timer(&mut self, now: Instant, events: &mut impl MuxEventSink) {
        let mut index = 0;
        while let Some(stream_id) = self.streams.ordered_id(index) {
            let action = {
                let stream = self
                    .streams
                    .get(&stream_id)
                    .expect("ordered stream id should exist");
                if stream.control.in_flight.iter().any(|(_, in_flight)| {
                    matches!(
                        in_flight.write_state,
                        InFlightWriteState::WaitingRetry { retry_at }
                            if retry_at <= now && in_flight.attempt >= self.config.retry_limit
                    )
                }) {
                    TimerAction::Fail
                } else if stream
                    .provisional_deadline()
                    .is_some_and(|deadline| deadline <= now)
                {
                    TimerAction::ExpireProvisional
                } else {
                    TimerAction::None
                }
            };

            match action {
                TimerAction::Fail => {
                    self.fail_stream_by_id(stream_id, MuxError::Timeout, events);
                }
                TimerAction::ExpireProvisional => {
                    let still_provisional = self
                        .streams
                        .get(&stream_id)
                        .is_some_and(StreamState::is_provisional);
                    if still_provisional {
                        self.streams.remove(&stream_id);
                        events.close(StreamFrameClose {
                            stream_id,
                            target: CloseTarget::Both,
                            code: CloseCode::PROTOCOL,
                            payload: Vec::new(),
                        });
                    }
                }
                TimerAction::None => {
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
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

    pub fn next_deadline(&self) -> Option<Instant> {
        let mut next = None;
        for stream in self.streams.values() {
            if let Some(deadline) = stream.control.ack_delay_deadline {
                next = min_deadline(next, deadline);
            }
            if let Some(deadline) = stream.provisional_deadline() {
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

    pub fn abort(&mut self, error: MuxError, events: &mut impl MuxEventSink) {
        while let Some(stream_id) = self.streams.first_id() {
            self.fail_stream_by_id(stream_id, error.clone(), events);
        }
    }

    fn next_stream_id(&mut self) -> StreamId {
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
        if !stream.is_provisional() {
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
        events: &mut impl MuxEventSink,
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
                            events.close(frame);
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
        events: &mut impl MuxEventSink,
    ) -> StreamDisposition {
        loop {
            let Some((_tx_seq, frame)) = stream.control.pop_next_committable() else {
                break;
            };

            if stream.is_provisional() && !matches!(frame, StreamFrame::Open(_)) {
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
        events: &mut impl MuxEventSink,
    ) {
        let StreamFrameOpen {
            request_head,
            request_prefix,
            ..
        } = frame;

        if !stream.is_provisional() {
            Self::queue_protocol_close(stream_id, stream, events);
            return;
        }

        let request_fin = request_prefix.as_ref().is_some_and(|chunk| chunk.fin);
        stream.role = StreamRole::Responder(ResponderStream {
            request: InboundState::new(),
            response: OutboundPhase::from_prefix(false),
            response_started: false,
        });
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
        events: &mut impl MuxEventSink,
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
        events: &mut impl MuxEventSink,
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
            StreamRole::Provisional(_) => {
                Self::drive_stream_outbound(stream_id, &mut stream.control, None)
            }
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
        events: &mut impl MuxEventSink,
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
                    events.outbound_failed(stream_id, MuxError::StreamProtocol);
                }
            }
            if let Some(inbound) = stream.inbound_mut(side) {
                if inbound.close() {
                    events.inbound_failed(stream_id, MuxError::StreamProtocol);
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
        events: &mut impl MuxEventSink,
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
            events.close(frame);
        }
    }

    fn fail_stream_by_id(
        &mut self,
        stream_id: StreamId,
        error: MuxError,
        events: &mut impl MuxEventSink,
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
                events.inbound_failed(stream_id, error.clone());
                if stream.response_started || stream.response.is_closed() {
                    events.outbound_failed(stream_id, error);
                }
            }
            StreamRole::Provisional(_) => {}
        }
        events.reaped(stream_id);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimerAction {
    None,
    Fail,
    ExpireProvisional,
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

#[derive(Debug)]
enum SeqRingInsertError {
    OutOfWindow,
    Occupied,
}

#[derive(Debug)]
struct SeqRing<const N: usize, T> {
    base_seq: StreamSeq,
    head: usize,
    len: usize,
    slots: [Option<T>; N],
}

impl<const N: usize, T> SeqRing<N, T> {
    fn new(base_seq: StreamSeq) -> Self {
        Self {
            base_seq,
            head: 0,
            len: 0,
            slots: array::from_fn(|_| None),
        }
    }

    fn base_seq(&self) -> StreamSeq {
        self.base_seq
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn clear_with_base(&mut self, base_seq: StreamSeq) {
        for slot in &mut self.slots {
            let _ = slot.take();
        }
        self.base_seq = base_seq;
        self.head = 0;
        self.len = 0;
    }

    fn contains_key(&self, seq: &StreamSeq) -> bool {
        self.get(seq).is_some()
    }

    fn accepts_seq(&self, seq: StreamSeq) -> bool {
        self.offset_for(seq).is_some()
    }

    fn get(&self, seq: &StreamSeq) -> Option<&T> {
        let index = self.index_for(*seq)?;
        self.slots[index].as_ref()
    }

    fn get_mut(&mut self, seq: &StreamSeq) -> Option<&mut T> {
        let index = self.index_for(*seq)?;
        self.slots[index].as_mut()
    }

    fn insert(&mut self, seq: StreamSeq, value: T) -> Result<(), SeqRingInsertError> {
        let index = self.index_for(seq).ok_or(SeqRingInsertError::OutOfWindow)?;
        if self.slots[index].is_some() {
            return Err(SeqRingInsertError::Occupied);
        }
        self.slots[index] = Some(value);
        self.len += 1;
        Ok(())
    }

    fn set(&mut self, seq: StreamSeq, value: T) -> Result<Option<T>, SeqRingInsertError> {
        let index = self.index_for(seq).ok_or(SeqRingInsertError::OutOfWindow)?;
        let previous = self.slots[index].replace(value);
        if previous.is_none() {
            self.len += 1;
        }
        Ok(previous)
    }

    fn remove(&mut self, seq: &StreamSeq) -> Option<T> {
        let index = self.index_for(*seq)?;
        let value = self.slots[index].take();
        if value.is_some() {
            self.len -= 1;
        }
        value
    }

    fn take_front(&mut self) -> Option<(StreamSeq, T)> {
        let value = self.slots[self.head].take()?;
        let seq = self.base_seq;
        self.len -= 1;
        self.head = self.next_index(self.head);
        self.base_seq = self.base_seq.next();
        Some((seq, value))
    }

    fn advance_empty_front_until(&mut self, limit_seq: StreamSeq) {
        while self.base_seq.serial_lt(limit_seq) && self.slots[self.head].is_none() {
            self.head = self.next_index(self.head);
            self.base_seq = self.base_seq.next();
        }
    }

    fn iter(&self) -> SeqRingIter<'_, N, T> {
        SeqRingIter {
            ring: self,
            offset: 0,
        }
    }

    fn bitmap(&self) -> u8 {
        debug_assert!(N <= 8);
        let mut bitmap = 0u8;
        for offset in 0..N {
            let index = self.index_for_offset(offset);
            if self.slots[index].is_some() {
                bitmap |= 1u8 << offset;
            }
        }
        bitmap
    }

    fn index_for(&self, seq: StreamSeq) -> Option<usize> {
        let offset = self.offset_for(seq)?;
        Some(self.index_for_offset(offset))
    }

    fn offset_for(&self, seq: StreamSeq) -> Option<usize> {
        let offset = self.base_seq.forward_distance_to(seq)? as usize;
        (offset < N).then_some(offset)
    }

    fn index_for_offset(&self, offset: usize) -> usize {
        (self.head + offset) % N
    }

    fn next_index(&self, index: usize) -> usize {
        (index + 1) % N
    }
}

struct SeqRingIter<'a, const N: usize, T> {
    ring: &'a SeqRing<N, T>,
    offset: usize,
}

impl<'a, const N: usize, T> Iterator for SeqRingIter<'a, N, T> {
    type Item = (StreamSeq, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        while self.offset < N {
            let offset = self.offset;
            self.offset += 1;
            let index = self.ring.index_for_offset(offset);
            if let Some(value) = self.ring.slots[index].as_ref() {
                return Some((self.ring.base_seq.add(offset as u32), value));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct OpenedStream {
        stream_id: StreamId,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct InboundChunk {
        stream_id: StreamId,
        bytes: Vec<u8>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct StreamFailure {
        stream_id: StreamId,
        error: MuxError,
    }

    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    struct Recorder {
        opened: Vec<OpenedStream>,
        closes: Vec<StreamFrameClose>,
        inbound_data: Vec<InboundChunk>,
        inbound_finished: Vec<StreamId>,
        inbound_failed: Vec<StreamFailure>,
        outbound_closed: Vec<StreamId>,
        outbound_failed: Vec<StreamFailure>,
        reaped: Vec<StreamId>,
    }

    impl MuxEventSink for Recorder {
        fn opened(
            &mut self,
            stream_id: StreamId,
            request_head: Vec<u8>,
            request_prefix: Option<BodyChunk>,
        ) {
            self.opened.push(OpenedStream {
                stream_id,
                request_head,
                request_prefix,
            });
        }

        fn inbound_data(&mut self, stream_id: StreamId, bytes: Vec<u8>) {
            self.inbound_data.push(InboundChunk { stream_id, bytes });
        }

        fn inbound_finished(&mut self, stream_id: StreamId) {
            self.inbound_finished.push(stream_id);
        }

        fn inbound_failed(&mut self, stream_id: StreamId, error: MuxError) {
            self.inbound_failed.push(StreamFailure { stream_id, error });
        }

        fn close(&mut self, frame: StreamFrameClose) {
            self.closes.push(frame);
        }

        fn outbound_closed(&mut self, stream_id: StreamId) {
            self.outbound_closed.push(stream_id);
        }

        fn outbound_failed(&mut self, stream_id: StreamId, error: MuxError) {
            self.outbound_failed
                .push(StreamFailure { stream_id, error });
        }

        fn reaped(&mut self, stream_id: StreamId) {
            self.reaped.push(stream_id);
        }
    }

    fn data_packet(stream_id: StreamId, tx_seq: u32, byte: u8) -> StreamBody {
        StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq(tx_seq),
            ack: StreamAck::EMPTY,
            valid_until: 0,
            frame: StreamFrame::Data(StreamFrameData {
                stream_id,
                chunk: BodyChunk {
                    bytes: vec![byte],
                    fin: false,
                },
            }),
        })
    }

    #[test]
    fn seq_ring_wraps_and_reuses_slots() {
        let mut ring = SeqRing::<4, u64>::new(StreamSeq(1));
        ring.insert(StreamSeq(1), 1).unwrap();
        ring.insert(StreamSeq(2), 2).unwrap();
        ring.insert(StreamSeq(3), 3).unwrap();

        assert_eq!(ring.take_front(), Some((StreamSeq(1), 1)));
        assert_eq!(ring.take_front(), Some((StreamSeq(2), 2)));

        ring.insert(StreamSeq(4), 4).unwrap();
        ring.insert(StreamSeq(5), 5).unwrap();

        let remaining: Vec<_> = ring.iter().map(|(seq, value)| (seq, *value)).collect();
        assert_eq!(
            remaining,
            vec![(StreamSeq(3), 3), (StreamSeq(4), 4), (StreamSeq(5), 5)]
        );
    }

    #[test]
    fn open_stream_enqueues_open_packet() {
        let now = Instant::now();
        let mut mux = Mux::new(MuxConfig::default());
        let stream_id = mux.open_stream(b"open".to_vec(), None);

        let outbound = mux.next_outbound(now, 7).unwrap();
        assert!(matches!(
            outbound.body,
            StreamBody::Message(StreamMessage {
                tx_seq: StreamSeq::START,
                ack: StreamAck::EMPTY,
                valid_until: 7,
                frame: StreamFrame::Open(StreamFrameOpen {
                    stream_id: id,
                    request_head,
                    request_prefix: None,
                }),
            }) if id == stream_id && request_head == b"open"
        ));
    }

    #[test]
    fn out_of_order_remote_stream_buffers_until_open_arrives() {
        let now = Instant::now();
        let mut mux = Mux::new(MuxConfig {
            local_namespace: StreamNamespace::Low,
            ..Default::default()
        });
        let stream_id = StreamId(StreamNamespace::High.bit() | 1);

        let mut events = Recorder::default();
        mux.receive(now, data_packet(stream_id, 2, b'h'), &mut events);
        assert!(events.opened.is_empty());
        assert!(events.inbound_data.is_empty());

        mux.receive(
            now,
            StreamBody::Message(StreamMessage {
                tx_seq: StreamSeq::START,
                ack: StreamAck::EMPTY,
                valid_until: 0,
                frame: StreamFrame::Open(StreamFrameOpen {
                    stream_id,
                    request_head: b"late-open".to_vec(),
                    request_prefix: None,
                }),
            }),
            &mut events,
        );

        assert_eq!(
            events.opened,
            vec![OpenedStream {
                stream_id,
                request_head: b"late-open".to_vec(),
                request_prefix: None,
            }]
        );
        assert_eq!(
            events.inbound_data,
            vec![InboundChunk {
                stream_id,
                bytes: vec![b'h'],
            }]
        );
    }

    #[test]
    fn ack_only_write_failure_requeues_without_spending_sequence_space() {
        let now = Instant::now();
        let config = MuxConfig::default();
        let mut mux = Mux::new(config);
        let stream_id = StreamId(StreamNamespace::High.bit() | 1);

        let mut events = Recorder::default();
        mux.receive(
            now,
            StreamBody::Message(StreamMessage {
                tx_seq: StreamSeq::START,
                ack: StreamAck::EMPTY,
                valid_until: 0,
                frame: StreamFrame::Open(StreamFrameOpen {
                    stream_id,
                    request_head: b"open".to_vec(),
                    request_prefix: None,
                }),
            }),
            &mut events,
        );
        assert_eq!(events.opened.len(), 1);

        mux.on_timer(now + config.ack_delay, &mut ());
        let ack_write = mux.next_outbound(now + config.ack_delay, 11).unwrap();
        assert!(matches!(
            ack_write.body,
            StreamBody::Ack(StreamAckBody {
                stream_id: id,
                ack: StreamAck {
                    base: StreamSeq::START,
                    bitmap: 0,
                },
                valid_until: 11,
            }) if id == stream_id
        ));

        mux.complete_outbound(
            now + config.ack_delay,
            ack_write.completion,
            Err(WriteError::SendFailed),
            &mut (),
        );
        let retry = mux.next_outbound(now + config.ack_delay, 12).unwrap();
        assert!(matches!(retry.body, StreamBody::Ack(_)));

        mux.complete_outbound(now + config.ack_delay, retry.completion, Ok(()), &mut ());
        mux.write_stream(stream_id, b"resp".to_vec()).unwrap();
        let response = mux.next_outbound(now, 13).unwrap();
        assert!(matches!(
            response.body,
            StreamBody::Message(StreamMessage {
                tx_seq: StreamSeq::START,
                valid_until: 13,
                frame: StreamFrame::Data(StreamFrameData {
                    stream_id: id,
                    chunk: BodyChunk { bytes, fin: false },
                }),
                ..
            }) if id == stream_id && bytes == b"resp"
        ));
    }

    #[test]
    fn fast_retransmit_resends_oldest_gap_when_threshold_met() {
        let now = Instant::now();
        let mut mux = Mux::new(MuxConfig {
            fast_retransmit_threshold: 2,
            ..Default::default()
        });
        let stream_id = mux.open_stream(b"open".to_vec(), None);
        let open = mux.next_outbound(now, 1).unwrap();
        mux.complete_outbound(now, open.completion, Ok(()), &mut ());
        mux.write_stream(stream_id, b"a".to_vec()).unwrap();
        mux.write_stream(stream_id, b"b".to_vec()).unwrap();
        mux.write_stream(stream_id, b"c".to_vec()).unwrap();
        mux.write_stream(stream_id, b"d".to_vec()).unwrap();
        let first = mux.next_outbound(now, 2).unwrap();
        let second = mux.next_outbound(now, 3).unwrap();
        let third = mux.next_outbound(now, 4).unwrap();
        let fourth = mux.next_outbound(now, 5).unwrap();
        mux.complete_outbound(now, first.completion, Ok(()), &mut ());
        mux.complete_outbound(now, second.completion, Ok(()), &mut ());
        mux.complete_outbound(now, third.completion, Ok(()), &mut ());
        mux.complete_outbound(now, fourth.completion, Ok(()), &mut ());

        mux.receive(
            now,
            StreamBody::Ack(StreamAckBody {
                stream_id,
                ack: StreamAck {
                    base: StreamSeq(2),
                    bitmap: 0b0000_0110,
                },
                valid_until: 0,
            }),
            &mut (),
        );

        let retransmit = mux.next_outbound(now, 6).unwrap();
        assert!(matches!(
            retransmit.body,
            StreamBody::Message(StreamMessage {
                tx_seq: StreamSeq(3),
                frame: StreamFrame::Data(_),
                ..
            })
        ));
    }

    #[test]
    fn late_failed_write_after_remote_close_ack_is_ignored() {
        let now = Instant::now();
        let mut mux = Mux::new(MuxConfig::default());
        let stream_id = mux.open_stream(b"open".to_vec(), None);
        let open = mux.next_outbound(now, 1).unwrap();

        let mut events = Recorder::default();
        mux.receive(
            now,
            StreamBody::Message(StreamMessage {
                tx_seq: StreamSeq::START,
                ack: StreamAck {
                    base: StreamSeq::START,
                    bitmap: 0,
                },
                valid_until: 0,
                frame: StreamFrame::Close(StreamFrameClose {
                    stream_id,
                    target: CloseTarget::Both,
                    code: CloseCode::PROTOCOL,
                    payload: Vec::new(),
                }),
            }),
            &mut events,
        );
        assert_eq!(
            events.closes,
            vec![StreamFrameClose {
                stream_id,
                target: CloseTarget::Both,
                code: CloseCode::PROTOCOL,
                payload: Vec::new(),
            }]
        );
        assert!(events.outbound_failed.is_empty());
        assert!(events.inbound_failed.is_empty());

        let mut late = Recorder::default();
        mux.complete_outbound(now, open.completion, Err(WriteError::SendFailed), &mut late);
        assert!(late.outbound_failed.is_empty());
        assert!(late.inbound_failed.is_empty());
    }
}
