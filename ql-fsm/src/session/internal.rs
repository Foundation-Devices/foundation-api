use std::time::Instant;

use ql_wire::{
    encrypted::{ping::PingBody, unpair::UnpairBody},
    CloseCode, CloseTarget, SessionBody, SessionCloseBody, SessionEnvelope, SessionSeq,
    StreamCloseFrame, StreamFrame, StreamId,
};

use super::{
    ring::SeqRingInsertError,
    state::{
        AckState, PendingChunk, PendingSessionBody, PendingStreamBody, SessionFsmState, StreamRole,
        StreamState, TxEntry,
    },
    SessionEvent, SessionFsm, SessionFsmConfig, SessionState, StreamError, StreamIncoming,
};

impl SessionFsm {
    pub fn new_inner(config: SessionFsmConfig, now: Instant) -> Self {
        Self {
            config,
            state: SessionFsmState {
                now,
                last_activity_at: now,
                last_inbound_at: now,
                session_state: SessionState::Open,
                next_stream_ordinal: 1,
                next_seq: SessionSeq(1),
                tx_ring: super::ring::SeqRing::new(SessionSeq(1)),
                rx_ring: super::ring::SeqRing::new(SessionSeq(1)),
                ack_state: AckState::Idle,
                pending_control: Default::default(),
                streams: Default::default(),
                ready_streams: Default::default(),
                events: Default::default(),
            },
        }
    }

    pub fn open_stream_inner(&mut self) -> Result<StreamId, StreamError> {
        self.ensure_session_open()?;
        let stream_id =
            StreamId(self.config.local_namespace.bit() | self.state.next_stream_ordinal);
        self.state.next_stream_ordinal = self.state.next_stream_ordinal.saturating_add(1);
        self.state
            .streams
            .insert(stream_id, StreamState::new(StreamRole::Initiator));
        Ok(stream_id)
    }

    pub fn write_stream_inner(
        &mut self,
        stream_id: StreamId,
        bytes: Vec<u8>,
    ) -> Result<(), StreamError> {
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

        let frame = StreamFrame {
            stream_id,
            offset: stream.next_send_offset,
            bytes,
            fin: false,
        };
        stream.next_send_offset += frame.bytes.len() as u64;
        stream
            .send_queue
            .push_back(PendingStreamBody::Stream(frame));
        Self::mark_stream_ready(&mut self.state, stream_id);
        Ok(())
    }

    pub fn finish_stream_inner(&mut self, stream_id: StreamId) -> Result<(), StreamError> {
        self.ensure_session_open()?;
        let stream = self
            .state
            .streams
            .get_mut(&stream_id)
            .ok_or(StreamError::MissingStream)?;
        if !stream.is_writable() {
            return Err(StreamError::NotWritable);
        }

        stream.outbound_finished = true;
        stream
            .send_queue
            .push_back(PendingStreamBody::Stream(StreamFrame {
                stream_id,
                offset: stream.next_send_offset,
                bytes: Vec::new(),
                fin: true,
            }));
        Self::mark_stream_ready(&mut self.state, stream_id);
        Ok(())
    }

    pub fn close_stream_inner(
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
        stream
            .send_queue
            .push_back(PendingStreamBody::StreamClose(StreamCloseFrame {
                stream_id,
                target,
                code,
                payload,
            }));
        Self::mark_stream_ready(&mut self.state, stream_id);
        Ok(())
    }

    pub fn queue_ping_inner(&mut self) -> Result<(), StreamError> {
        self.ensure_session_open()?;
        self.state.pending_control.ping = true;
        Ok(())
    }

    pub fn queue_unpair_inner(&mut self) -> Result<(), StreamError> {
        self.ensure_session_open()?;
        self.state.pending_control.unpair = true;
        Ok(())
    }

    pub fn close_session_inner(&mut self, code: CloseCode) {
        self.fail_session(SessionCloseBody { code });
    }

    pub fn receive_inner(&mut self, envelope: SessionEnvelope) {
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

    pub fn next_outbound_inner(&mut self) -> Option<SessionEnvelope> {
        self.collect_timeouts();
        let pending = self.next_pending_body()?;
        if !self.state.tx_ring.accepts_seq(self.state.next_seq) {
            if pending.priority {
                self.requeue_pending_front(pending);
            }
            return None;
        }

        let seq = self.state.next_seq;
        self.state.next_seq = SessionSeq(seq.0 + 1);
        let ack = self.state.current_ack();
        self.state.clear_ack_schedule();
        let envelope = SessionEnvelope {
            seq,
            ack,
            body: pending.body.clone(),
        };
        let entry = TxEntry {
            pending,
            sent_at: self.state.now,
        };
        self.state.last_activity_at = self.state.now;
        if entry.pending.retransmit {
            let _ = self.state.tx_ring.insert(seq, entry);
        }
        Some(envelope)
    }

    pub fn on_timer_inner(&mut self) {
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

    pub fn next_deadline_inner(&self) -> Option<Instant> {
        let ack_deadline = match self.state.ack_state {
            AckState::Idle => None,
            AckState::Immediate => Some(self.state.now),
            AckState::Delayed { due_at } => Some(due_at),
        };
        let retransmit_deadline = self
            .state
            .tx_ring
            .iter()
            .map(|(_, entry)| entry.sent_at + self.config.retransmit_timeout)
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

    pub fn take_next_event_inner(&mut self) -> Option<SessionEvent> {
        self.state.events.pop_front()
    }

    pub fn take_next_inbound_inner(&mut self, stream_id: StreamId) -> Option<StreamIncoming> {
        self.state
            .streams
            .get_mut(&stream_id)
            .and_then(|stream| stream.inbound_queue.pop_front())
    }

    pub fn session_state_inner(&self) -> SessionState {
        self.state.session_state
    }

    fn next_pending_body(&mut self) -> Option<PendingSessionBody> {
        if let Some(close) = self.state.pending_control.close.take() {
            return Some(PendingSessionBody {
                body: SessionBody::Close(close),
                retransmit: true,
                priority: true,
            });
        }
        if self.state.pending_control.unpair {
            self.state.pending_control.unpair = false;
            return Some(PendingSessionBody {
                body: SessionBody::Unpair(UnpairBody),
                retransmit: true,
                priority: true,
            });
        }
        if self.state.pending_control.ping {
            self.state.pending_control.ping = false;
            return Some(PendingSessionBody {
                body: SessionBody::Ping(PingBody),
                retransmit: false,
                priority: true,
            });
        }

        while let Some(stream_id) = self.state.ready_streams.pop_front() {
            let Some(stream) = self.state.streams.get_mut(&stream_id) else {
                continue;
            };
            stream.ready_enqueued = false;
            let Some(item) = stream.send_queue.pop_front() else {
                continue;
            };
            if !stream.send_queue.is_empty() {
                Self::mark_stream_ready(&mut self.state, stream_id);
            }
            return Some(PendingSessionBody {
                body: item.to_session_body(),
                retransmit: true,
                priority: true,
            });
        }

        let ack_due = match self.state.ack_state {
            AckState::Immediate => true,
            AckState::Delayed { due_at } => due_at <= self.state.now,
            AckState::Idle => false,
        };
        ack_due.then_some(PendingSessionBody {
            body: SessionBody::Ack,
            retransmit: false,
            priority: false,
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
            .filter_map(|(seq, _)| Self::ack_covers(ack, seq).then_some(seq))
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
            .filter_map(|(seq, entry)| {
                (entry.sent_at + self.config.retransmit_timeout <= self.state.now).then_some(seq)
            })
            .collect();

        for seq in expired {
            if let Some(entry) = self.state.tx_ring.remove(&seq) {
                if entry.pending.retransmit {
                    self.requeue_pending_front(entry.pending);
                }
            }
        }

        self.state
            .tx_ring
            .advance_empty_front_until(self.state.next_seq);
    }

    fn requeue_pending_front(&mut self, pending: PendingSessionBody) {
        match pending.body {
            SessionBody::Stream(frame) => {
                if let Some(stream) = self.state.streams.get_mut(&frame.stream_id) {
                    let stream_id = frame.stream_id;
                    stream
                        .send_queue
                        .push_front(PendingStreamBody::Stream(frame));
                    Self::mark_stream_ready_front(&mut self.state, stream_id);
                }
            }
            SessionBody::StreamClose(frame) => {
                if let Some(stream) = self.state.streams.get_mut(&frame.stream_id) {
                    let stream_id = frame.stream_id;
                    stream
                        .send_queue
                        .push_front(PendingStreamBody::StreamClose(frame));
                    Self::mark_stream_ready_front(&mut self.state, stream_id);
                }
            }
            body => match body {
                SessionBody::Ack => {}
                SessionBody::Ping(_) => self.state.pending_control.ping = true,
                SessionBody::Unpair(_) => self.state.pending_control.unpair = true,
                SessionBody::Close(close) => self.state.pending_control.close = Some(close),
                SessionBody::Stream(_) | SessionBody::StreamClose(_) => unreachable!(),
            },
        }
    }

    fn mark_stream_ready(state: &mut SessionFsmState, stream_id: StreamId) {
        let Some(stream) = state.streams.get_mut(&stream_id) else {
            return;
        };
        if stream.ready_enqueued {
            return;
        }
        stream.ready_enqueued = true;
        state.ready_streams.push_back(stream_id);
    }

    fn mark_stream_ready_front(state: &mut SessionFsmState, stream_id: StreamId) {
        let Some(stream) = state.streams.get_mut(&stream_id) else {
            return;
        };
        if stream.ready_enqueued {
            return;
        }
        stream.ready_enqueued = true;
        state.ready_streams.push_front(stream_id);
    }

    fn handle_stream_frame(&mut self, frame: StreamFrame) {
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
        if stream.inbound_discarding {
            return;
        }
        if stream.inbound_closed || stream.inbound_finished {
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
            Self::commit_inbound_frame(stream, frame);
            Self::drain_pending_recv(stream);
            self.state
                .events
                .push_back(SessionEvent::Readable(stream_id));
            return;
        }

        if Self::insert_pending_chunk(
            stream,
            frame.offset,
            PendingChunk {
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

    fn handle_stream_close(&mut self, frame: StreamCloseFrame) {
        let Some(stream) = self.state.streams.get_mut(&frame.stream_id) else {
            self.fail_session(SessionCloseBody {
                code: CloseCode::PROTOCOL,
            });
            return;
        };

        if Self::target_affects_inbound(stream.role, frame.target) {
            stream.inbound_closed = true;
            stream.inbound_discarding = false;
            stream.pending_recv.clear();
            stream
                .inbound_queue
                .push_back(StreamIncoming::Closed(frame.clone()));
            self.state
                .events
                .push_back(SessionEvent::Readable(frame.stream_id));
        }
        if Self::target_affects_outbound(stream.role, frame.target) {
            stream.outbound_closed = true;
            stream.send_queue.clear();
            self.state
                .events
                .push_back(SessionEvent::WritableClosed(frame.stream_id));
        }
    }

    fn apply_close_to_stream(stream: &mut StreamState, target: CloseTarget) {
        if Self::target_affects_inbound(stream.role, target) {
            stream.inbound_discarding = true;
            stream.pending_recv.clear();
        }
        if Self::target_affects_outbound(stream.role, target) {
            stream.outbound_closed = true;
            stream.outbound_finished = true;
            stream.send_queue.clear();
        }
    }

    fn target_affects_inbound(role: StreamRole, target: CloseTarget) -> bool {
        matches!(target, CloseTarget::Both) || role.inbound_target() == target
    }

    fn target_affects_outbound(role: StreamRole, target: CloseTarget) -> bool {
        matches!(target, CloseTarget::Both) || role.outbound_target() == target
    }

    fn commit_inbound_frame(stream: &mut StreamState, frame: StreamFrame) {
        Self::commit_inbound_chunk(stream, frame.bytes, frame.fin);
    }

    fn commit_inbound_chunk(stream: &mut StreamState, bytes: Vec<u8>, fin: bool) {
        stream.next_recv_offset += bytes.len() as u64;
        if !bytes.is_empty() {
            stream.inbound_queue.push_back(StreamIncoming::Data(bytes));
        }
        if fin {
            stream.inbound_finished = true;
            stream.inbound_queue.push_back(StreamIncoming::Finished);
        }
    }

    fn drain_pending_recv(stream: &mut StreamState) {
        while let Some(chunk) = stream.pending_recv.remove(&stream.next_recv_offset) {
            Self::commit_inbound_chunk(stream, chunk.bytes, chunk.fin);
            if stream.inbound_finished {
                break;
            }
        }
    }

    fn insert_pending_chunk(
        stream: &mut StreamState,
        offset: u64,
        chunk: PendingChunk,
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
        self.state.ready_streams.clear();
        self.state.streams.clear();
    }
}
