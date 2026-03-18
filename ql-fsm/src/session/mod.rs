pub(crate) mod ring;
pub(crate) mod state;

#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};

use ql_wire::{
    CloseCode, CloseTarget, PingBody, SessionBody, SessionCloseBody, SessionEnvelope, SessionSeq,
    StreamChunk, StreamClose, StreamId, UnpairBody, XID,
};

use self::{
    ring::SeqRingInsertError,
    state::{
        AckState, InboundState, OutboundState, PendingRxChunk, PendingSessionBody,
        SessionFsmState, StreamRole, StreamState, TxEntry, TxState,
    },
};

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
    Unpaired,
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
                events: Default::default(),
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
        Ok(())
    }

    pub fn read_stream(
        &mut self,
        stream_id: StreamId,
        out: &mut [u8],
    ) -> Result<usize, StreamError> {
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
        Ok(written)
    }

    pub fn queue_ping(&mut self) -> Result<(), StreamError> {
        self.ensure_session_open()?;
        self.state.pending_control.ping = true;
        Ok(())
    }

    pub fn queue_unpair(&mut self) -> Result<(), StreamError> {
        self.ensure_session_open()?;
        self.state.pending_control.unpair = true;
        Ok(())
    }

    pub fn receive(&mut self, now: Instant, envelope: SessionEnvelope) {
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
        match self.state.rx_ring.insert(seq, ()) {
            Ok(()) => {
                let out_of_order = seq != self.state.rx_ring.base_seq();
                self.state.rx_ring.advance_occupied_front();
                if !matches!(envelope.body, SessionBody::Ack) {
                    self.schedule_ack(out_of_order);
                }
            }
            Err(SeqRingInsertError::OutOfWindow) => {
                self.fail_session(SessionCloseBody {
                    code: CloseCode::PROTOCOL,
                });
                return;
            }
            Err(SeqRingInsertError::Occupied) => {
                if !matches!(envelope.body, SessionBody::Ack) {
                    self.schedule_ack(true);
                }
                return;
            }
        }

        match envelope.body {
            SessionBody::Ack => {}
            SessionBody::Ping(_) => {}
            SessionBody::Unpair(_) => {
                self.state.session_state = SessionState::Closed;
                self.clear_streams();
                self.state.events.push_back(SessionEvent::Unpaired);
            }
            SessionBody::Close(close) => {
                self.state.session_state = SessionState::Closed;
                self.clear_streams();
                self.state
                    .events
                    .push_back(SessionEvent::SessionClosed(close));
            }
            SessionBody::Stream(frame) => self.handle_stream_frame(frame),
            SessionBody::StreamClose(frame) => self.handle_stream_close(frame),
        }
    }

    pub fn take_next_write(&mut self, now: Instant) -> Option<SessionEnvelope> {
        self.state.now = now;
        self.collect_timeouts();
        let ack = self.state.current_ack();
        loop {
            let Some(seq) = self
                .state
                .tx_ring
                .iter()
                .find_map(|(seq, entry)| matches!(entry.state, TxState::Pending).then_some(seq))
            else {
                break;
            };
            let Some(body) = self
                .state
                .tx_ring
                .get(&seq)
                .map(|entry| entry.pending.body.clone())
            else {
                return None;
            };
            if !self.should_retry_body(&body) {
                let _ = self.state.tx_ring.remove(&seq);
                self.state
                    .tx_ring
                    .advance_empty_front_until(self.state.next_seq);
                continue;
            }

            let Some(entry) = self.state.tx_ring.get_mut(&seq) else {
                return None;
            };
            entry.state = TxState::Issued;
            return Some(SessionEnvelope { seq, ack, body });
        }

        if !self.state.tx_ring.accepts_seq(self.state.next_seq) {
            return None;
        }

        let pending = self.next_pending_body()?;
        let seq = self.state.next_seq;
        self.state.next_seq = SessionSeq(seq.0 + 1);
        let body = pending.body.clone();
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

        Some(SessionEnvelope { seq, ack, body })
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

    pub fn return_write(&mut self, seq: SessionSeq) {
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

    #[cfg(test)]
    pub fn next_outbound(&mut self, now: Instant) -> Option<SessionEnvelope> {
        let envelope = self.take_next_write(now)?;
        self.confirm_write(now, envelope.seq);
        Some(envelope)
    }

    pub fn on_timer(&mut self, now: Instant) {
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
            self.fail_session(SessionCloseBody {
                code: CloseCode::TIMEOUT,
            });
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

    pub fn take_next_event(&mut self) -> Option<SessionEvent> {
        self.state.events.pop_front()
    }

    #[cfg(test)]
    pub fn session_state(&self) -> SessionState {
        self.state.session_state
    }

    pub fn has_pending_stream_work(&self) -> bool {
        self.state.streams.values().any(|stream| {
            stream.pending_close.is_some()
                || !stream.send_buf.is_empty()
                || matches!(stream.outbound_state, OutboundState::FinQueued)
        })
    }

    fn next_pending_body(&mut self) -> Option<PendingSessionBody> {
        if let Some(close) = self.state.pending_control.close.take() {
            return Some(PendingSessionBody {
                body: SessionBody::Close(close),
                retransmit: true,
            });
        }
        if self.state.pending_control.unpair {
            self.state.pending_control.unpair = false;
            return Some(PendingSessionBody {
                body: SessionBody::Unpair(UnpairBody),
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
                    if let Some(close) = stream.pending_close.take() {
                        Some(SessionBody::StreamClose(close))
                    } else if !stream.send_buf.is_empty() {
                        let len = stream.send_buf.len().min(self.config.stream_chunk_size);
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
                            offset: stream.next_send_offset,
                            bytes,
                            fin,
                        };
                        stream.next_send_offset += frame.bytes.len() as u64;
                        Some(SessionBody::Stream(frame))
                    } else if matches!(stream.outbound_state, OutboundState::FinQueued) {
                        stream.outbound_state = OutboundState::Finished;
                        Some(SessionBody::Stream(StreamChunk {
                            stream_id,
                            offset: stream.next_send_offset,
                            bytes: Vec::new(),
                            fin: true,
                        }))
                    } else {
                        None
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
        let acked: Vec<_> = self
            .state
            .tx_ring
            .iter()
            .filter_map(|(seq, entry)| {
                (matches!(entry.state, TxState::Sent { .. }) && Self::ack_covers(ack, seq))
                    .then_some(seq)
            })
            .collect();
        for seq in acked {
            let _ = self.state.tx_ring.remove(&seq);
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
            SessionBody::Ping(_) | SessionBody::Unpair(_) => {
                self.state.session_state == SessionState::Open
            }
            SessionBody::Close(_) => true,
            SessionBody::Stream(frame) => {
                self.state.session_state == SessionState::Open
                    && self
                        .state
                        .streams
                        .get(&frame.stream_id)
                        .is_some_and(|stream| !matches!(stream.outbound_state, OutboundState::Closed))
            }
            SessionBody::StreamClose(frame) => {
                self.state.session_state == SessionState::Open
                    && self.state.streams.contains_key(&frame.stream_id)
            }
        }
    }

    fn handle_stream_frame(&mut self, frame: StreamChunk) {
        let stream_id = frame.stream_id;
        let remote_namespace = self.config.local_namespace.remote();
        if !self.state.streams.contains_key(&stream_id) {
            if !remote_namespace.matches(stream_id) {
                self.fail_session(SessionCloseBody {
                    code: CloseCode::PROTOCOL,
                });
                return;
            }
            self.state
                .streams
                .insert(stream_id, StreamState::new(StreamRole::Responder));
            self.state.events.push_back(SessionEvent::Opened(stream_id));
        }

        let Some(stream) = self.state.streams.get_mut(&stream_id) else {
            return;
        };
        if matches!(stream.inbound_state, InboundState::Discarding) {
            return;
        }
        if matches!(
            stream.inbound_state,
            InboundState::Closed(_) | InboundState::Finished
        ) {
            if frame.offset + frame.bytes.len() as u64 <= stream.next_recv_offset {
                return;
            }
            self.fail_session(SessionCloseBody {
                code: CloseCode::PROTOCOL,
            });
            return;
        }

        if frame.offset < stream.next_recv_offset {
            let frame_end = frame.offset + frame.bytes.len() as u64;
            if frame_end <= stream.next_recv_offset {
                return;
            }
            self.fail_session(SessionCloseBody {
                code: CloseCode::PROTOCOL,
            });
            return;
        }

        if frame.offset == stream.next_recv_offset {
            let was_readable = !stream.recv_buf.is_empty();
            let was_finished = matches!(stream.inbound_state, InboundState::Finished);
            Self::commit_inbound_frame(stream, frame);
            Self::drain_pending_recv(stream);
            let became_readable = !was_readable && !stream.recv_buf.is_empty();
            let became_finished =
                !was_finished && matches!(stream.inbound_state, InboundState::Finished);
            if became_readable {
                self.state.events.push_back(SessionEvent::Readable(stream_id));
            }
            if became_finished {
                self.state.events.push_back(SessionEvent::Finished(stream_id));
            }
            return;
        }

        if Self::insert_pending_chunk(
            stream,
            frame.offset,
            PendingRxChunk {
                bytes: frame.bytes,
                fin: frame.fin,
            },
        )
        .is_err()
        {
            self.fail_session(SessionCloseBody {
                code: CloseCode::PROTOCOL,
            });
        }
    }

    fn handle_stream_close(&mut self, frame: StreamClose) {
        let Some(stream) = self.state.streams.get_mut(&frame.stream_id) else {
            self.fail_session(SessionCloseBody {
                code: CloseCode::PROTOCOL,
            });
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
            stream.pending_recv.clear();
            self.state.events.push_back(SessionEvent::Closed(frame.clone()));
        }
        if Self::target_affects_outbound(stream.role, frame.target)
            && !matches!(stream.outbound_state, OutboundState::Closed)
        {
            stream.outbound_state = OutboundState::Closed;
            stream.send_buf.clear();
            stream.pending_close = None;
            self.state
                .events
                .push_back(SessionEvent::WritableClosed(frame.stream_id));
        }
    }

    fn apply_close_to_stream(stream: &mut StreamState, target: CloseTarget) {
        if Self::target_affects_inbound(stream.role, target) {
            stream.inbound_state = InboundState::Discarding;
            stream.recv_buf.clear();
            stream.pending_recv.clear();
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

    fn commit_inbound_frame(stream: &mut StreamState, frame: StreamChunk) {
        Self::commit_inbound_chunk(stream, frame.bytes, frame.fin);
    }

    fn commit_inbound_chunk(stream: &mut StreamState, bytes: Vec<u8>, fin: bool) {
        stream.next_recv_offset += bytes.len() as u64;
        if !bytes.is_empty() {
            stream.recv_buf.extend(bytes);
        }
        if fin {
            stream.inbound_state = InboundState::Finished;
        }
    }

    fn drain_pending_recv(stream: &mut StreamState) {
        while let Some(chunk) = stream.pending_recv.remove(&stream.next_recv_offset) {
            Self::commit_inbound_chunk(stream, chunk.bytes, chunk.fin);
            if matches!(stream.inbound_state, InboundState::Finished) {
                break;
            }
        }
    }

    fn insert_pending_chunk(
        stream: &mut StreamState,
        offset: u64,
        chunk: PendingRxChunk,
    ) -> Result<(), ()> {
        let end = chunk.end_offset(offset);

        if let Some((&prev_offset, prev)) = stream.pending_recv.range(..=offset).next_back() {
            let prev_end = prev.end_offset(prev_offset);
            if prev_end > offset {
                if prev_offset == offset && prev.bytes == chunk.bytes && prev.fin == chunk.fin {
                    return Ok(());
                }
                return Err(());
            }
        }

        if let Some((&next_offset, _)) = stream.pending_recv.range(offset..).next() {
            if end > next_offset {
                return Err(());
            }
        }

        stream.pending_recv.insert(offset, chunk);
        Ok(())
    }

    fn fail_session(&mut self, close: SessionCloseBody) {
        if self.state.session_state == SessionState::Closed {
            return;
        }

        self.state.session_state = SessionState::Closed;
        self.clear_streams();
        self.state.pending_control = Default::default();
        self.state.pending_control.close = Some(close.clone());
        self.state
            .events
            .push_back(SessionEvent::SessionClosed(close));
    }

    fn clear_streams(&mut self) {
        self.state.next_stream_index = 0;
        self.state.streams.clear();
    }
}
