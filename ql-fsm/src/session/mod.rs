pub(crate) mod ring;
pub(crate) mod state;
pub(crate) mod stream_window;

#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};

use indexmap::map::Entry;
use ql_wire::{
    CloseCode, CloseTarget, PingBody, SessionAck, SessionBody, SessionCloseBody, SessionEnvelope,
    SessionSeq, StreamChunk, StreamClose, StreamId, XID,
};

use self::{
    state::{
        AckState, InboundState, OutboundState, PendingSessionBody, SessionFsmState,
        StreamOpenState, StreamRole, StreamState, TxEntry, TxState,
    },
    stream_window::{RecvInsertOutcome, RxChunk},
};

struct RejectNoAck;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamNamespace {
    Low,
    High,
}

impl StreamNamespace {
    const BIT: u32 = 1 << 31;

    pub fn for_local(local: XID, peer: XID) -> Self {
        match local.0.cmp(&peer.0) {
            std::cmp::Ordering::Less | std::cmp::Ordering::Equal => Self::Low,
            std::cmp::Ordering::Greater => Self::High,
        }
    }

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
pub struct SessionFsmConfig {
    pub local_namespace: StreamNamespace,
    pub stream_chunk_size: usize,
    pub ack_delay: Duration,
    pub retransmit_timeout: Duration,
    pub keepalive_interval: Duration,
    pub peer_timeout: Duration,
}

impl Default for SessionFsmConfig {
    fn default() -> Self {
        Self {
            local_namespace: StreamNamespace::Low,
            stream_chunk_size: 16 * 1024,
            ack_delay: Duration::from_millis(5),
            retransmit_timeout: Duration::from_millis(150),
            keepalive_interval: Duration::from_secs(10),
            peer_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    Opened(StreamId),
    Readable(StreamId),
    Finished(StreamId),
    Closed(StreamClose),
    WritableClosed(StreamId),
    SessionClosed(SessionCloseBody),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    #[error("missing stream")]
    MissingStream,
    #[error("stream is not writable")]
    NotWritable,
    #[error("session is closed")]
    SessionClosed,
}

pub struct SessionFsm {
    config: SessionFsmConfig,
    state: SessionFsmState,
}

impl SessionFsm {
    pub fn new(mut config: SessionFsmConfig, now: Instant) -> Self {
        config.stream_chunk_size = config.stream_chunk_size.max(1);
        Self {
            config,
            state: SessionFsmState {
                now,
                last_activity_at: now,
                last_inbound_at: now,
                session_state: SessionState::Open,
                next_stream_ordinal: 1,
                next_seq: SessionSeq(1),
                tx_ring: ring::SeqRing::new(SessionSeq(1)),
                rx_ring: ring::SeqRing::new(SessionSeq(1)),
                ack_state: AckState::Idle,
                pending_control: Default::default(),
                streams: Default::default(),
                next_stream_index: 0,
            },
        }
    }

    pub fn open_stream(&mut self) -> Result<StreamId, StreamError> {
        self.ensure_session_open()?;
        let stream_id =
            StreamId(self.config.local_namespace.bit() | self.state.next_stream_ordinal);
        self.state.next_stream_ordinal = self.state.next_stream_ordinal.saturating_add(1);
        self.state
            .streams
            .insert(stream_id, StreamState::new(StreamRole::Initiator));
        Ok(stream_id)
    }

    pub fn write_stream(&mut self, stream_id: StreamId, bytes: Vec<u8>) -> Result<(), StreamError> {
        self.ensure_session_open()?;
        if bytes.is_empty() {
            return Ok(());
        }

        let stream = self
            .state
            .streams
            .get_mut(&stream_id)
            .ok_or(StreamError::MissingStream)?;
        if !stream.is_writable() {
            return Err(StreamError::NotWritable);
        }

        stream.send_buf.extend(bytes);
        Ok(())
    }

    pub fn finish_stream(&mut self, stream_id: StreamId) -> Result<(), StreamError> {
        self.ensure_session_open()?;
        let stream = self
            .state
            .streams
            .get_mut(&stream_id)
            .ok_or(StreamError::MissingStream)?;
        if !stream.is_writable() {
            return Err(StreamError::NotWritable);
        }

        stream.outbound_state = OutboundState::FinQueued;
        Ok(())
    }

    pub fn close_stream(
        &mut self,
        stream_id: StreamId,
        target: CloseTarget,
        code: CloseCode,
        payload: Vec<u8>,
    ) -> Result<(), StreamError> {
        self.ensure_session_open()?;
        {
            let stream = self
                .state
                .streams
                .get_mut(&stream_id)
                .ok_or(StreamError::MissingStream)?;

            Self::apply_close_to_stream(stream, target);
            stream.pending_close = Some(StreamClose {
                stream_id,
                target,
                code,
                payload,
            });
        }
        self.try_reap_stream(stream_id);
        Ok(())
    }

    pub fn read_stream(
        &mut self,
        stream_id: StreamId,
        out: &mut [u8],
    ) -> Result<usize, StreamError> {
        let written = {
            let stream = self
                .state
                .streams
                .get_mut(&stream_id)
                .ok_or(StreamError::MissingStream)?;
            if out.is_empty() || stream.recv_buf.is_empty() {
                return Ok(0);
            }

            let (front, back) = stream.recv_buf.as_slices();
            let front_len = front.len().min(out.len());
            out[..front_len].copy_from_slice(&front[..front_len]);

            let mut written = front_len;
            let remaining = out.len() - front_len;
            if remaining > 0 {
                let back_len = back.len().min(remaining);
                out[written..written + back_len].copy_from_slice(&back[..back_len]);
                written += back_len;
            }

            stream.recv_buf.drain(..written);
            written
        };
        self.try_reap_stream(stream_id);
        Ok(written)
    }

    pub fn stream_available_bytes(&self, stream_id: StreamId) -> Result<usize, StreamError> {
        let stream = self
            .state
            .streams
            .get(&stream_id)
            .ok_or(StreamError::MissingStream)?;
        Ok(stream.recv_buf.len())
    }

    pub fn queue_ping(&mut self) -> Result<(), StreamError> {
        self.ensure_session_open()?;
        self.state.pending_control.ping = true;
        Ok(())
    }

    pub fn receive(
        &mut self,
        now: Instant,
        envelope: SessionEnvelope,
        mut emit: impl FnMut(SessionEvent),
    ) {
        self.state.now = now;
        self.collect_timeouts();
        self.process_ack(envelope.ack);

        if self.state.session_state == SessionState::Closed {
            return;
        }

        self.state.last_activity_at = self.state.now;
        self.state.last_inbound_at = self.state.now;

        let seq = envelope.seq;
        if seq.0 < self.state.rx_ring.base_seq().0 || self.state.rx_ring.contains_key(&seq) {
            if !matches!(envelope.body, SessionBody::Ack) {
                self.schedule_ack(true);
            }
            return;
        }
        if !self.state.rx_ring.accepts_seq(seq) {
            self.fail_session(
                SessionCloseBody {
                    code: CloseCode::PROTOCOL,
                },
                &mut emit,
            );
            return;
        }

        let out_of_order = seq != self.state.rx_ring.base_seq();
        let body_kind_is_ack = matches!(envelope.body, SessionBody::Ack);
        let apply_inbound_body = match envelope.body {
            SessionBody::Ack | SessionBody::Ping(_) => Ok(()),
            SessionBody::Close(close) => {
                self.state.session_state = SessionState::Closed;
                self.clear_streams();
                emit(SessionEvent::SessionClosed(close));
                Ok(())
            }
            SessionBody::Stream(frame) => self.handle_stream_frame(frame, &mut emit),
            SessionBody::StreamClose(frame) => {
                self.handle_stream_close(frame, &mut emit);
                Ok(())
            }
        };
        if apply_inbound_body.is_err() {
            return;
        }

        match self.state.rx_ring.insert(seq, ()) {
            Ok(()) => {
                self.state.rx_ring.advance_occupied_front();
                if !body_kind_is_ack {
                    self.schedule_ack(out_of_order);
                }
            }
            Err(e) => {
                unreachable!("seq window was pre-validated before body handling {e:?}");
            }
        }
    }

    pub fn confirm_write(&mut self, now: Instant, seq: SessionSeq) {
        self.state.now = now;
        let Some((retransmit, should_clear_ack)) = self.state.tx_ring.get(&seq).map(|entry| {
            (
                entry.pending.retransmit,
                matches!(entry.pending.body, SessionBody::Ack),
            )
        }) else {
            return;
        };
        debug_assert!(matches!(
            self.state.tx_ring.get(&seq).map(|entry| entry.state),
            Some(TxState::Issued)
        ));
        if !matches!(
            self.state.tx_ring.get(&seq).map(|entry| entry.state),
            Some(TxState::Issued)
        ) {
            return;
        }

        self.state.last_activity_at = self.state.now;
        if retransmit {
            if let Some(entry) = self.state.tx_ring.get_mut(&seq) {
                entry.state = TxState::Sent {
                    sent_at: self.state.now,
                };
            }
        } else {
            let _ = self.state.tx_ring.remove(&seq);
            self.state
                .tx_ring
                .advance_empty_front_until(self.state.next_seq);
            if should_clear_ack {
                self.state.clear_ack_schedule();
            }
        }
    }

    pub fn reject_write(&mut self, seq: SessionSeq) {
        debug_assert!(matches!(
            self.state.tx_ring.get(&seq).map(|entry| entry.state),
            Some(TxState::Issued)
        ));
        let Some(entry) = self.state.tx_ring.get_mut(&seq) else {
            return;
        };
        if !matches!(entry.state, TxState::Issued) {
            return;
        }
        entry.state = TxState::Pending;
    }

    pub fn on_timer(&mut self, now: Instant, mut emit: impl FnMut(SessionEvent)) {
        self.state.now = now;
        self.collect_timeouts();
        if self.state.session_state == SessionState::Closed {
            return;
        }
        if let AckState::Delayed { due_at } = self.state.ack_state {
            if due_at <= self.state.now {
                self.state.ack_state = AckState::Immediate;
            }
        }
        if !self.config.peer_timeout.is_zero()
            && self.state.last_inbound_at + self.config.peer_timeout <= self.state.now
        {
            self.fail_session(
                SessionCloseBody {
                    code: CloseCode::TIMEOUT,
                },
                &mut emit,
            );
            return;
        }
        if !self.config.keepalive_interval.is_zero()
            && self.state.last_activity_at + self.config.keepalive_interval <= self.state.now
        {
            self.state.pending_control.ping = true;
        }
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        let ack_deadline = match self.state.ack_state {
            AckState::Idle => None,
            AckState::Immediate => Some(self.state.now),
            AckState::Delayed { due_at } => Some(due_at),
        };
        let retransmit_deadline = self
            .state
            .tx_ring
            .iter()
            .filter_map(|(_, entry)| match entry.state {
                TxState::Sent { sent_at } => Some(sent_at + self.config.retransmit_timeout),
                TxState::Pending | TxState::Issued => None,
            })
            .min();
        let keepalive_deadline = (self.state.session_state == SessionState::Open
            && !self.config.keepalive_interval.is_zero()
            && !self.state.pending_control.ping)
            .then_some(self.state.last_activity_at + self.config.keepalive_interval);
        let peer_timeout_deadline = (self.state.session_state == SessionState::Open
            && !self.config.peer_timeout.is_zero())
        .then_some(self.state.last_inbound_at + self.config.peer_timeout);
        [
            ack_deadline,
            retransmit_deadline,
            keepalive_deadline,
            peer_timeout_deadline,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    pub fn has_pending_stream_work(&self) -> bool {
        self.state.streams.values().any(|stream| {
            stream.pending_close.is_some()
                || !stream.send_buf.is_empty()
                || matches!(stream.outbound_state, OutboundState::FinQueued)
        })
    }

    pub fn take_next_write(
        &mut self,
        now: Instant,
    ) -> Option<(SessionSeq, SessionAck, &SessionBody)> {
        self.state.now = now;
        self.collect_timeouts();
        let ack = self.state.current_ack();
        let seq = self
            .take_pending_retransmit()
            .or_else(|| self.take_fresh_write())?;
        let entry = self.state.tx_ring.get(&seq).unwrap();
        Some((seq, ack, &entry.pending.body))
    }

    fn take_pending_retransmit(&mut self) -> Option<SessionSeq> {
        let base_seq = self.state.tx_ring.base_seq().0;
        let next_seq = self.state.next_seq.0;

        for seq in (base_seq..next_seq).map(SessionSeq) {
            let should_retry = match self.state.tx_ring.get(&seq) {
                Some(entry) if matches!(entry.state, TxState::Pending) => {
                    self.should_retry_body(&entry.pending.body)
                }
                _ => continue,
            };

            if !should_retry {
                let _ = self.state.tx_ring.remove(&seq);
                continue;
            }

            self.state
                .tx_ring
                .advance_empty_front_until(self.state.next_seq);
            let entry = self.state.tx_ring.get_mut(&seq).unwrap();
            entry.state = TxState::Issued;
            return Some(seq);
        }

        self.state
            .tx_ring
            .advance_empty_front_until(self.state.next_seq);

        None
    }

    fn take_fresh_write(&mut self) -> Option<SessionSeq> {
        if !self.state.tx_ring.accepts_seq(self.state.next_seq) {
            return None;
        }

        let pending = self.next_pending_body()?;
        let seq = self.state.next_seq;
        self.state.next_seq = SessionSeq(seq.0 + 1);
        self.state
            .tx_ring
            .insert(
                seq,
                TxEntry {
                    pending,
                    state: TxState::Issued,
                },
            )
            .unwrap();
        Some(seq)
    }

    fn next_pending_body(&mut self) -> Option<PendingSessionBody> {
        if let Some(close) = self.state.pending_control.close.take() {
            return Some(PendingSessionBody {
                body: SessionBody::Close(close),
                retransmit: true,
            });
        }
        if self.state.pending_control.ping {
            self.state.pending_control.ping = false;
            return Some(PendingSessionBody {
                body: SessionBody::Ping(PingBody),
                retransmit: false,
            });
        }

        let len = self.state.streams.len();
        if len > 0 {
            let start = self.state.next_stream_index % len;
            for offset in 0..len {
                let index = (start + offset) % len;
                let has_pending = self
                    .state
                    .streams
                    .get_index(index)
                    .is_some_and(|(_, stream)| {
                        stream.pending_close.is_some()
                            || !stream.send_buf.is_empty()
                            || matches!(stream.outbound_state, OutboundState::FinQueued)
                    });
                if !has_pending {
                    continue;
                }

                let body = {
                    let Some((&stream_id, stream)) = self.state.streams.get_index_mut(index) else {
                        continue;
                    };
                    match stream.open_state {
                        StreamOpenState::PendingSend => {
                            let body = Self::take_stream_frame(
                                stream,
                                stream_id,
                                self.config.stream_chunk_size,
                            )
                            .map(SessionBody::Stream);
                            if body.is_some() {
                                stream.open_state = StreamOpenState::WaitingForAck;
                            }
                            body
                        }
                        StreamOpenState::WaitingForAck => None,
                        StreamOpenState::Opened => {
                            if let Some(close) = stream.pending_close.take() {
                                Some(SessionBody::StreamClose(close))
                            } else {
                                Self::take_stream_frame(
                                    stream,
                                    stream_id,
                                    self.config.stream_chunk_size,
                                )
                                .map(SessionBody::Stream)
                            }
                        }
                    }
                };
                let Some(body) = body else {
                    continue;
                };
                self.state.next_stream_index = (index + 1) % len;
                return Some(PendingSessionBody {
                    body,
                    retransmit: true,
                });
            }
        }

        let ack_due = match self.state.ack_state {
            AckState::Immediate => true,
            AckState::Delayed { due_at } => due_at <= self.state.now,
            AckState::Idle => false,
        };
        ack_due.then_some(PendingSessionBody {
            body: SessionBody::Ack,
            retransmit: false,
        })
    }

    fn ensure_session_open(&self) -> Result<(), StreamError> {
        if self.state.session_state == SessionState::Closed {
            Err(StreamError::SessionClosed)
        } else {
            Ok(())
        }
    }

    fn process_ack(&mut self, ack: ql_wire::SessionAck) {
        loop {
            let Some((seq, stream_id, opens_stream)) =
                self.state.tx_ring.iter().find_map(|(seq, entry)| {
                    if !matches!(entry.state, TxState::Sent { .. }) || !Self::ack_covers(ack, seq) {
                        return None;
                    }

                    let (stream_id, opens_stream) = match &entry.pending.body {
                        SessionBody::Stream(frame) => (Some(frame.stream_id), frame.chunk_seq == 0),
                        SessionBody::StreamClose(frame) => (Some(frame.stream_id), false),
                        _ => (None, false),
                    };

                    Some((seq, stream_id, opens_stream))
                })
            else {
                break;
            };

            let _ = self.state.tx_ring.remove(&seq);
            if let Some(stream_id) = stream_id {
                if opens_stream {
                    if let Some(stream) = self.state.streams.get_mut(&stream_id) {
                        if matches!(stream.open_state, StreamOpenState::WaitingForAck) {
                            stream.open_state = StreamOpenState::Opened;
                        }
                    }
                }
                self.try_reap_stream(stream_id);
            }
        }
        self.state
            .tx_ring
            .advance_empty_front_until(self.state.next_seq);
    }

    fn ack_covers(ack: ql_wire::SessionAck, seq: SessionSeq) -> bool {
        if seq.0 <= ack.base.0 {
            return true;
        }
        let delta = seq.0 - ack.base.0;
        if delta == 0 || delta > 64 {
            return false;
        }
        (ack.bitmap & (1u64 << (delta - 1))) != 0
    }

    fn schedule_ack(&mut self, immediate: bool) {
        self.state.ack_state = match self.state.ack_state {
            AckState::Immediate => AckState::Immediate,
            _ if immediate || self.config.ack_delay.is_zero() => AckState::Immediate,
            AckState::Delayed { due_at } => AckState::Delayed { due_at },
            AckState::Idle => AckState::Delayed {
                due_at: self.state.now + self.config.ack_delay,
            },
        };
    }

    fn collect_timeouts(&mut self) {
        let expired: Vec<_> = self
            .state
            .tx_ring
            .iter()
            .filter_map(|(seq, entry)| match entry.state {
                TxState::Sent { sent_at }
                    if sent_at + self.config.retransmit_timeout <= self.state.now =>
                {
                    Some(seq)
                }
                TxState::Pending | TxState::Issued | TxState::Sent { .. } => None,
            })
            .collect();

        for seq in expired {
            let Some((retransmit, body)) = self
                .state
                .tx_ring
                .get(&seq)
                .map(|entry| (entry.pending.retransmit, entry.pending.body.clone()))
            else {
                continue;
            };
            if retransmit && self.should_retry_body(&body) {
                if let Some(entry) = self.state.tx_ring.get_mut(&seq) {
                    entry.state = TxState::Pending;
                }
            } else {
                let _ = self.state.tx_ring.remove(&seq);
                if matches!(body, SessionBody::Ack) {
                    self.state.clear_ack_schedule();
                }
            }
        }

        self.state
            .tx_ring
            .advance_empty_front_until(self.state.next_seq);
    }

    fn should_retry_body(&self, body: &SessionBody) -> bool {
        match body {
            SessionBody::Ack => true,
            SessionBody::Ping(_) => self.state.session_state == SessionState::Open,
            SessionBody::Close(_) => true,
            SessionBody::Stream(frame) => {
                self.state.session_state == SessionState::Open
                    && self
                        .state
                        .streams
                        .get(&frame.stream_id)
                        .is_some_and(|stream| {
                            !matches!(stream.outbound_state, OutboundState::Closed)
                                || (matches!(stream.open_state, StreamOpenState::WaitingForAck)
                                    && frame.chunk_seq == 0)
                        })
            }
            SessionBody::StreamClose(frame) => {
                self.state.session_state == SessionState::Open
                    && self.state.streams.contains_key(&frame.stream_id)
            }
        }
    }

    fn handle_stream_frame(
        &mut self,
        frame: StreamChunk,
        emit: &mut impl FnMut(SessionEvent),
    ) -> Result<(), RejectNoAck> {
        let StreamChunk {
            stream_id,
            chunk_seq,
            bytes,
            fin,
        } = frame;
        let remote_namespace = self.config.local_namespace.remote();
        let stream = match self.state.streams.entry(stream_id) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                if !remote_namespace.matches(stream_id) {
                    self.fail_session(
                        SessionCloseBody {
                            code: CloseCode::PROTOCOL,
                        },
                        emit,
                    );
                    return Ok(());
                }
                if chunk_seq != 0 {
                    return Err(RejectNoAck);
                }
                emit(SessionEvent::Opened(stream_id));
                entry.insert(StreamState::new(StreamRole::Responder))
            }
        };
        match stream.inbound_state {
            InboundState::Open => (),
            InboundState::Finished | InboundState::Closed(_) => {
                if chunk_seq < stream.recv_window.next_chunk_seq() {
                    return Ok(());
                }
                self.fail_session(
                    SessionCloseBody {
                        code: CloseCode::PROTOCOL,
                    },
                    emit,
                );
                return Ok(());
            }
            InboundState::Discarding => return Ok(()),
        }

        let was_readable = !stream.recv_buf.is_empty();
        let outcome = stream.recv_window.insert(chunk_seq, RxChunk { bytes, fin });

        match outcome {
            RecvInsertOutcome::Inserted => {
                Self::drain_recv_window(stream);
                if !was_readable && !stream.recv_buf.is_empty() {
                    emit(SessionEvent::Readable(stream_id));
                }
                if matches!(stream.inbound_state, InboundState::Finished) {
                    emit(SessionEvent::Finished(stream_id));
                }
                self.try_reap_stream(stream_id);
                Ok(())
            }
            RecvInsertOutcome::Duplicate => Ok(()),
            RecvInsertOutcome::RejectNoAck => Err(RejectNoAck),
            RecvInsertOutcome::Conflict => {
                self.fail_session(
                    SessionCloseBody {
                        code: CloseCode::PROTOCOL,
                    },
                    emit,
                );
                Ok(())
            }
        }
    }

    fn handle_stream_close(&mut self, frame: StreamClose, emit: &mut impl FnMut(SessionEvent)) {
        let Some(stream) = self.state.streams.get_mut(&frame.stream_id) else {
            self.fail_session(
                SessionCloseBody {
                    code: CloseCode::PROTOCOL,
                },
                emit,
            );
            return;
        };

        if Self::target_affects_inbound(stream.role, frame.target)
            && !matches!(
                stream.inbound_state,
                InboundState::Closed(_) | InboundState::Discarding
            )
        {
            stream.inbound_state = InboundState::Closed(frame.clone());
            stream.recv_buf.clear();
            stream.recv_window.clear();
            emit(SessionEvent::Closed(frame.clone()));
        }
        if Self::target_affects_outbound(stream.role, frame.target)
            && !matches!(stream.outbound_state, OutboundState::Closed)
        {
            stream.outbound_state = OutboundState::Closed;
            stream.send_buf.clear();
            stream.pending_close = None;
            emit(SessionEvent::WritableClosed(frame.stream_id));
        }
        self.try_reap_stream(frame.stream_id);
    }

    fn apply_close_to_stream(stream: &mut StreamState, target: CloseTarget) {
        if Self::target_affects_inbound(stream.role, target) {
            stream.inbound_state = InboundState::Discarding;
            stream.recv_buf.clear();
            stream.recv_window.clear();
        }
        if Self::target_affects_outbound(stream.role, target) {
            stream.outbound_state = OutboundState::Closed;
            stream.send_buf.clear();
        }
    }

    fn target_affects_inbound(role: StreamRole, target: CloseTarget) -> bool {
        matches!(target, CloseTarget::Both) || role.inbound_target() == target
    }

    fn target_affects_outbound(role: StreamRole, target: CloseTarget) -> bool {
        matches!(target, CloseTarget::Both) || role.outbound_target() == target
    }

    fn drain_recv_window(stream: &mut StreamState) {
        while let Some(chunk) = stream.recv_window.pop_contiguous() {
            let RxChunk { bytes, fin } = chunk;
            stream.recv_buf.extend(bytes);
            if fin {
                stream.inbound_state = InboundState::Finished;
                break;
            }
        }
    }

    fn take_stream_frame(
        stream: &mut StreamState,
        stream_id: StreamId,
        chunk_size: usize,
    ) -> Option<StreamChunk> {
        if !stream.send_buf.is_empty() {
            let len = stream.send_buf.len().min(chunk_size);
            let bytes: Vec<_> = stream.send_buf.drain(..len).collect();
            let fin = if stream.send_buf.is_empty()
                && matches!(stream.outbound_state, OutboundState::FinQueued)
            {
                stream.outbound_state = OutboundState::Finished;
                true
            } else {
                false
            };
            let frame = StreamChunk {
                stream_id,
                chunk_seq: stream.next_send_chunk_seq,
                bytes,
                fin,
            };
            stream.next_send_chunk_seq += 1;
            return Some(frame);
        }

        if matches!(stream.outbound_state, OutboundState::FinQueued) {
            stream.outbound_state = OutboundState::Finished;
            return Some(StreamChunk {
                stream_id,
                chunk_seq: stream.next_send_chunk_seq,
                bytes: Vec::new(),
                fin: true,
            });
        }

        None
    }

    fn stream_is_reapable(&self, stream_id: StreamId, stream: &StreamState) -> bool {
        let tx_ring_references_stream =
            self.state
                .tx_ring
                .iter()
                .any(|(_, entry)| match &entry.pending.body {
                    SessionBody::Stream(frame) => frame.stream_id == stream_id,
                    SessionBody::StreamClose(frame) => frame.stream_id == stream_id,
                    _ => false,
                });

        if tx_ring_references_stream {
            return false;
        }

        if !stream.send_buf.is_empty()
            || !stream.recv_buf.is_empty()
            || !stream.recv_window.is_empty()
        {
            return false;
        }

        match stream.open_state {
            StreamOpenState::WaitingForAck => false,
            StreamOpenState::PendingSend => matches!(stream.outbound_state, OutboundState::Closed),
            StreamOpenState::Opened => {
                stream.pending_close.is_none()
                    && matches!(
                        stream.inbound_state,
                        InboundState::Finished | InboundState::Closed(_) | InboundState::Discarding
                    )
                    && matches!(
                        stream.outbound_state,
                        OutboundState::Finished | OutboundState::Closed
                    )
            }
        }
    }

    fn try_reap_stream(&mut self, stream_id: StreamId) {
        let should_reap = self
            .state
            .streams
            .get(&stream_id)
            .is_some_and(|stream| self.stream_is_reapable(stream_id, stream));
        if !should_reap {
            return;
        }

        let Some(index) = self.state.streams.get_index_of(&stream_id) else {
            return;
        };
        self.state.streams.shift_remove(&stream_id);

        if self.state.streams.is_empty() {
            self.state.next_stream_index = 0;
            return;
        }
        if index < self.state.next_stream_index {
            self.state.next_stream_index -= 1;
        }
        if self.state.next_stream_index >= self.state.streams.len() {
            self.state.next_stream_index %= self.state.streams.len();
        }
    }

    fn fail_session(&mut self, close: SessionCloseBody, emit: &mut impl FnMut(SessionEvent)) {
        if self.state.session_state == SessionState::Closed {
            return;
        }

        self.state.session_state = SessionState::Closed;
        self.clear_streams();
        self.state.pending_control = Default::default();
        self.state.pending_control.close = Some(close.clone());
        emit(SessionEvent::SessionClosed(close));
    }

    fn clear_streams(&mut self) {
        self.state.next_stream_index = 0;
        self.state.streams.clear();
    }
}
