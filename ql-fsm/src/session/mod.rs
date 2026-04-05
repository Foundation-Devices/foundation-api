pub(crate) mod received_records;
pub(crate) mod remote_stream_history;
pub(crate) mod state;
pub(crate) mod stream_parity;
pub(crate) mod stream_rx;
pub(crate) mod stream_tx;
pub(crate) mod tracked;

#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};

use indexmap::{map::Entry, IndexMap};
use ql_wire::{
    CloseTarget, RecordAck, RecordSeq, SessionClose, SessionCloseCode, SessionFrame,
    SessionRecordBuilder, StreamClose, StreamCloseCode, StreamData, StreamId, StreamWindow,
    WireError,
};

use self::{
    received_records::{ReceiveOutcome, ReceivedRecords},
    remote_stream_history::RemoteStreamHistory,
    state::{AckState, InboundState, OutboundState, SessionFsmState, StreamRole, StreamState},
    stream_parity::StreamParity,
    stream_rx::{StreamReadIter, StreamRxError},
    stream_tx::StreamTxRange,
    tracked::{TrackedFrame, TrackedRecord, TrackedStreamData},
};

#[derive(Debug, Clone, Copy)]
pub struct SessionFsmConfig {
    pub local_parity: StreamParity,
    pub record_max_size: usize,
    pub ack_delay: Duration,
    pub retransmit_timeout: Duration,
    pub keepalive_interval: Duration,
    pub peer_timeout: Duration,
    pub stream_send_buffer_size: usize,
    pub stream_receive_buffer_size: u32,
    pub initial_peer_stream_receive_window: u32,
}

impl Default for SessionFsmConfig {
    fn default() -> Self {
        Self {
            local_parity: StreamParity::Even,
            record_max_size: 8 * 1024,
            ack_delay: Duration::from_millis(5),
            retransmit_timeout: Duration::from_millis(150),
            keepalive_interval: Duration::from_secs(10),
            peer_timeout: Duration::from_secs(30),
            stream_send_buffer_size: 16 * 1024,
            stream_receive_buffer_size: 16 * 1024,
            initial_peer_stream_receive_window: 16 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    Opened(StreamId),
    Readable(StreamId),
    Writable(StreamId),
    Finished(StreamId),
    Closed(StreamClose),
    WritableClosed(StreamId),
    SessionClosed(SessionClose),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    MissingStream,
    NotWritable,
    InvalidRead,
    SessionClosed,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::MissingStream => "missing stream",
            Self::NotWritable => "stream is not writable",
            Self::InvalidRead => "invalid read commit",
            Self::SessionClosed => "session is closed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for StreamError {}

pub struct SessionFsm {
    config: SessionFsmConfig,
    state: SessionFsmState,
}

impl SessionFsm {
    pub fn new(mut config: SessionFsmConfig, now: Instant) -> Self {
        config.record_max_size = config
            .record_max_size
            .max(SessionRecordBuilder::WIRE_PREFIX_LEN);
        config.stream_send_buffer_size = config.stream_send_buffer_size.max(1);
        config.stream_receive_buffer_size = config.stream_receive_buffer_size.max(1);
        Self {
            config,
            state: SessionFsmState {
                now,
                last_activity_at: now,
                last_inbound_at: now,
                session_state: SessionState::Open,
                next_stream_ordinal: 0,
                next_record_seq: RecordSeq(0),
                next_write_id: 0,
                tracked_records: Default::default(),
                received_records: ReceivedRecords::default(),
                ack_state: AckState::Idle,
                pending_control: Default::default(),
                streams: Default::default(),
                next_stream_index: 0,
                remote_stream_history: RemoteStreamHistory::new(config.local_parity.remote()),
            },
        }
    }

    pub fn open_stream(&mut self) -> Result<StreamId, StreamError> {
        self.ensure_session_open()?;
        let stream_id = self
            .config
            .local_parity
            .make_stream_id(self.state.next_stream_ordinal);
        self.state.next_stream_ordinal = self.state.next_stream_ordinal.saturating_add(1);
        self.state.streams.insert(
            stream_id,
            StreamState::new(
                StreamRole::Initiator,
                self.config.stream_receive_buffer_size,
                self.config.initial_peer_stream_receive_window,
            ),
        );
        Ok(stream_id)
    }

    pub fn write_stream(
        &mut self,
        stream_id: StreamId,
        bytes: &[u8],
    ) -> Result<usize, StreamError> {
        self.ensure_session_open()?;
        let stream = self
            .state
            .streams
            .get_mut(&stream_id)
            .ok_or(StreamError::MissingStream)?;
        if !stream.is_writable() {
            return Err(StreamError::NotWritable);
        }

        let accepted = bytes
            .len()
            .min(stream.send_capacity(self.config.stream_send_buffer_size));
        stream.tx.append(&bytes[..accepted]);
        Ok(accepted)
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
        stream.tx.queue_fin();
        stream.outbound_state = OutboundState::FinQueued;
        Ok(())
    }

    pub fn close_stream(
        &mut self,
        stream_id: StreamId,
        target: CloseTarget,
        code: StreamCloseCode,
    ) -> Result<(), StreamError> {
        self.ensure_session_open()?;
        {
            let stream = self
                .state
                .streams
                .get_mut(&stream_id)
                .ok_or(StreamError::MissingStream)?;
            Self::apply_local_close_to_stream(stream, target);
            stream.pending_close = Some(StreamClose {
                stream_id,
                target,
                code,
            });
        }
        self.try_reap_stream(stream_id);
        Ok(())
    }

    pub fn stream_read(&self, stream_id: StreamId) -> Option<StreamReadIter<'_>> {
        let stream = self.state.streams.get(&stream_id)?;
        Some(stream.rx.bytes())
    }

    pub fn stream_read_commit(
        &mut self,
        stream_id: StreamId,
        len: usize,
    ) -> Result<(), StreamError> {
        let stream = self
            .state
            .streams
            .get_mut(&stream_id)
            .ok_or(StreamError::MissingStream)?;
        if len > stream.readable_bytes() {
            return Err(StreamError::InvalidRead);
        }
        stream.rx.consume(len);
        if stream.recv_limit() > stream.advertised_max_offset {
            stream.pending_window = true;
        }
        self.try_reap_stream(stream_id);
        Ok(())
    }

    pub fn stream_available_bytes(&self, stream_id: StreamId) -> Option<usize> {
        let stream = self.state.streams.get(&stream_id)?;
        Some(stream.readable_bytes())
    }

    pub fn queue_ping(&mut self) -> Result<(), StreamError> {
        self.ensure_session_open()?;
        self.state.pending_control.ping = true;
        Ok(())
    }

    pub fn receive<'a, I>(
        &mut self,
        now: Instant,
        seq: RecordSeq,
        frames: I,
        mut emit: impl FnMut(SessionEvent),
    ) where
        I: IntoIterator<Item = Result<SessionFrame<&'a [u8]>, WireError>>,
    {
        self.state.now = now;
        self.collect_timeouts();
        self.state.last_activity_at = self.state.now;
        self.state.last_inbound_at = self.state.now;

        if self.state.session_state == SessionState::Closed {
            return;
        }

        let mut received_records = self.state.received_records.clone();
        let out_of_order = match received_records.insert(seq) {
            ReceiveOutcome::TooOld => return,
            ReceiveOutcome::Duplicate => {
                self.schedule_ack(true);
                return;
            }
            ReceiveOutcome::New { out_of_order } => out_of_order,
        };

        let mut ack_eliciting = false;
        let mut handled_close = false;

        for frame in frames {
            let Ok(frame) = frame else {
                self.fail_session(
                    SessionClose {
                        code: SessionCloseCode::PROTOCOL,
                    },
                    &mut emit,
                );
                return;
            };
            ack_eliciting |= !matches!(frame, SessionFrame::Ack(_));
            match frame {
                SessionFrame::Ping => {}
                SessionFrame::Ack(ack) => self.process_record_ack(&ack, &mut emit),
                SessionFrame::StreamData(frame) => {
                    if self.handle_stream_data(&frame, &mut emit).is_err() {
                        return;
                    }
                }
                SessionFrame::StreamWindow(frame) => self.handle_stream_window(&frame, &mut emit),
                SessionFrame::StreamClose(frame) => {
                    if self.handle_stream_close(&frame, &mut emit).is_err() {
                        return;
                    }
                }
                SessionFrame::Close(close) => {
                    self.handle_session_close(close, &mut emit);
                    handled_close = true;
                    break;
                }
            }
        }

        // commit after processing
        self.state.received_records = received_records;

        if handled_close {
            return;
        }

        if ack_eliciting {
            self.schedule_ack(out_of_order);
        }
    }

    pub fn confirm_write(&mut self, now: Instant, write_id: u64) {
        self.state.now = now;
        let Some(record) = self.state.tracked_records.get_mut(&write_id) else {
            return;
        };
        if record.sent_at.is_some() {
            return;
        }
        self.state.last_activity_at = now;
        record.sent_at = Some(now);
    }

    pub fn reject_write(&mut self, write_id: u64) {
        if self
            .state
            .tracked_records
            .get(&write_id)
            .is_some_and(|record| record.sent_at.is_some())
        {
            return;
        }
        let Some(record) = self.state.tracked_records.shift_remove(&write_id) else {
            return;
        };
        restore_tracked_record(
            self.state.now,
            &mut self.state.ack_state,
            &mut self.state.pending_control,
            &mut self.state.streams,
            record,
        );
    }

    pub fn on_timer(&mut self, now: Instant, mut emit: impl FnMut(SessionEvent)) {
        self.state.now = now;
        self.collect_timeouts();
        if !self.config.peer_timeout.is_zero()
            && self.state.last_inbound_at + self.config.peer_timeout <= self.state.now
        {
            self.fail_session(
                SessionClose {
                    code: SessionCloseCode::TIMEOUT,
                },
                &mut emit,
            );
            return;
        }
        if self.state.session_state == SessionState::Open
            && !self.config.keepalive_interval.is_zero()
            && self.state.last_activity_at + self.config.keepalive_interval <= self.state.now
        {
            self.state.pending_control.ping = true;
        }
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        let ack_deadline = match self.state.ack_state {
            AckState::Idle => None,
            AckState::Dirty { due_at } => Some(due_at),
        };
        let retransmit_deadline = self
            .state
            .tracked_records
            .values()
            .filter_map(|record| {
                record
                    .sent_at
                    .map(|sent_at| sent_at + self.config.retransmit_timeout)
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

    pub fn take_next_write(
        &mut self,
        now: Instant,
    ) -> Option<(Option<u64>, RecordSeq, SessionRecordBuilder)> {
        self.state.now = now;
        self.collect_timeouts();

        let (builder, outbound) = self.build_next_record()?;
        let seq = outbound.seq;

        let should_track = outbound.ping_included
            || !outbound.window_updates.is_empty()
            || !outbound.frames.is_empty();

        let write_id = should_track.then(|| {
            let write_id = self.state.next_write_id;
            self.state.next_write_id = self.state.next_write_id.wrapping_add(1);
            self.state.tracked_records.insert(write_id, outbound);
            write_id
        });

        Some((write_id, seq, builder))
    }

    fn build_next_record(&mut self) -> Option<(SessionRecordBuilder, TrackedRecord)> {
        let seq = self.state.next_record_seq;
        let mut builder = SessionRecordBuilder::new(self.config.record_max_size);
        let mut outbound = TrackedRecord {
            seq,
            frames: Vec::new(),
            ack_included: false,
            ping_included: false,
            window_updates: Vec::new(),
            sent_at: None,
        };

        if let Some(close) = self.state.pending_control.close.take() {
            if builder.push_close(&close) {
                outbound.frames.push(TrackedFrame::Close(close.clone()));
            } else {
                self.state.pending_control.close = Some(close);
            }
        }

        self.push_next_pending_stream_close(&mut builder, &mut outbound);

        if self.state.pending_control.ping && builder.push_ping() {
            self.state.pending_control.ping = false;
            outbound.ping_included = true;
        }

        self.push_next_pending_stream_window(&mut builder, &mut outbound);

        self.push_next_stream_data(&mut builder, &mut outbound);

        if let Some((ack, due_at)) = self.pending_ack() {
            if (!builder.is_empty() || due_at <= self.state.now) && builder.push_ack(&ack) {
                outbound.ack_included = true;
                self.state.ack_state = AckState::Idle;
            }
        }

        if builder.is_empty() {
            return None;
        }

        self.state.next_record_seq = RecordSeq(self.state.next_record_seq.0.saturating_add(1));
        Some((builder, outbound))
    }

    fn push_next_pending_stream_close(
        &mut self,
        builder: &mut SessionRecordBuilder,
        outbound: &mut TrackedRecord,
    ) {
        let len = self.state.streams.len();
        if len == 0 {
            return;
        }

        let start = self.state.next_stream_index % len;
        for offset in 0..len {
            let index = (start + offset) % len;
            let stream = self.state.streams.get_index_mut(index).unwrap().1;
            let Some(close) = stream.pending_close.as_ref() else {
                continue;
            };
            if !builder.push_stream_close(close) {
                break;
            }

            outbound.frames.push(TrackedFrame::StreamClose(
                stream.pending_close.take().unwrap(),
            ));
        }
    }

    fn push_next_pending_stream_window(
        &mut self,
        builder: &mut SessionRecordBuilder,
        outbound: &mut TrackedRecord,
    ) {
        let len = self.state.streams.len();
        if len == 0 {
            return;
        }

        let start = self.state.next_stream_index % len;
        for offset in 0..len {
            let index = (start + offset) % len;
            let (&stream_id, stream) = self.state.streams.get_index_mut(index).unwrap();
            if !stream.pending_window {
                continue;
            }
            let frame = StreamWindow {
                stream_id,
                maximum_offset: stream.recv_limit(),
            };
            if !builder.push_stream_window(&frame) {
                break;
            }

            stream.pending_window = false;
            stream.advertised_max_offset = frame.maximum_offset;
            outbound
                .window_updates
                .push((stream_id, frame.maximum_offset));
        }
    }

    fn push_next_stream_data(
        &mut self,
        builder: &mut SessionRecordBuilder,
        outbound: &mut TrackedRecord,
    ) {
        const OVERHEAD: usize =
            1 + std::mem::size_of::<u16>() + StreamData::<Vec<u8>>::MIN_WIRE_SIZE;

        let len = self.state.streams.len();
        if len == 0 {
            return;
        }

        let start = self.state.next_stream_index % len;
        let mut next_index = start;

        for offset in 0..len {
            let Some(max_payload) = builder.remaining_capacity().checked_sub(OVERHEAD) else {
                break;
            };

            let index = (start + offset) % len;
            let (&stream_id, stream) = self.state.streams.get_index_mut(index).unwrap();
            if matches!(stream.outbound_state, OutboundState::Closed) {
                continue;
            }
            let Some(candidate) = stream.tx.next_range(max_payload, stream.peer_max_offset) else {
                continue;
            };
            let frame = StreamData {
                stream_id,
                offset: candidate.offset,
                fin: candidate.fin,
                bytes: stream.tx.ranged_bytes(candidate),
            };
            let res = builder.push_stream_data(&frame);
            assert!(res, "builder has capacity");

            stream.tx.mark_in_flight(candidate);
            if candidate.fin {
                stream.outbound_state = OutboundState::Finished;
            }
            outbound
                .frames
                .push(TrackedFrame::StreamData(TrackedStreamData {
                    stream_id,
                    offset: candidate.offset,
                    len: candidate.len,
                    fin: candidate.fin,
                }));
            next_index = (index + 1) % len;
        }

        self.state.next_stream_index = next_index;
    }

    fn ensure_session_open(&self) -> Result<(), StreamError> {
        if self.state.session_state == SessionState::Closed {
            Err(StreamError::SessionClosed)
        } else {
            Ok(())
        }
    }

    fn process_record_ack(&mut self, ack: &RecordAck, emit: &mut impl FnMut(SessionEvent)) {
        let stream_send_buffer_size = self.config.stream_send_buffer_size;
        {
            let tracked_records = &mut self.state.tracked_records;
            let streams = &mut self.state.streams;
            for (_, record) in tracked_records.extract_if(.., |_, record| {
                record.sent_at.is_some() && ack.contains(record.seq.0)
            }) {
                for frame in &record.frames {
                    acknowledge_tracked_frame(streams, stream_send_buffer_size, frame, emit);
                }
            }
        }
        self.reap_reapable_streams();
    }

    fn schedule_ack(&mut self, immediate: bool) {
        schedule_ack(
            &mut self.state.ack_state,
            if immediate {
                self.state.now
            } else {
                self.state.now + self.config.ack_delay
            },
        );
    }

    fn pending_ack(&self) -> Option<(RecordAck, Instant)> {
        match self.state.ack_state {
            AckState::Idle => None,
            AckState::Dirty { due_at } => {
                self.state.received_records.ack().map(|ack| (ack, due_at))
            }
        }
    }

    fn collect_timeouts(&mut self) {
        let retransmit_timeout = self.config.retransmit_timeout;
        for (_, record) in self.state.tracked_records.extract_if(.., |_, record| {
            record
                .sent_at
                .is_some_and(|sent_at| sent_at + retransmit_timeout <= self.state.now)
        }) {
            restore_tracked_record(
                self.state.now,
                &mut self.state.ack_state,
                &mut self.state.pending_control,
                &mut self.state.streams,
                record,
            );
        }
    }

    fn handle_stream_data(
        &mut self,
        frame: &StreamData<&[u8]>,
        emit: &mut impl FnMut(SessionEvent),
    ) -> Result<(), ()> {
        let stream_id = frame.stream_id;
        let stream = match self.state.streams.entry(stream_id) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                match classify_missing_stream(
                    self.config.local_parity,
                    self.state.next_stream_ordinal,
                    stream_id,
                    &mut self.state.remote_stream_history,
                ) {
                    MissingStreamAction::Create => {}
                    MissingStreamAction::Ignore => return Ok(()),
                    MissingStreamAction::FailProtocol => {
                        self.fail_session(
                            SessionClose {
                                code: SessionCloseCode::PROTOCOL,
                            },
                            emit,
                        );
                        return Err(());
                    }
                }

                emit(SessionEvent::Opened(stream_id));
                entry.insert(StreamState::new(
                    StreamRole::Responder,
                    self.config.stream_receive_buffer_size,
                    self.config.initial_peer_stream_receive_window,
                ))
            }
        };

        match stream.inbound_state {
            InboundState::Open => {}
            InboundState::Discarding => return Ok(()),
            InboundState::Finished | InboundState::Closed(_) => {
                if frame.offset + frame.bytes.len() as u64 <= stream.rx.start_offset() {
                    return Ok(());
                }
                self.fail_session(
                    SessionClose {
                        code: SessionCloseCode::PROTOCOL,
                    },
                    emit,
                );
                return Err(());
            }
        }

        let was_readable = stream.readable_bytes() > 0;
        let insert = stream.rx.insert(frame.offset, frame.fin, frame.bytes);
        match insert {
            Ok(outcome) => {
                if !was_readable && outcome.newly_readable_bytes > 0 {
                    emit(SessionEvent::Readable(stream_id));
                }
                if outcome.became_complete {
                    stream.inbound_state = InboundState::Finished;
                    emit(SessionEvent::Finished(stream_id));
                }
                self.try_reap_stream(stream_id);
                Ok(())
            }
            Err(
                StreamRxError::OutOfWindow
                | StreamRxError::InconsistentFinalOffset
                | StreamRxError::FinalOffsetBeforeBufferedData
                | StreamRxError::BeyondFinalOffset
                | StreamRxError::TooManyMissingRanges
                | StreamRxError::OffsetOverflow,
            ) => {
                self.fail_session(
                    SessionClose {
                        code: SessionCloseCode::PROTOCOL,
                    },
                    emit,
                );
                Err(())
            }
        }
    }

    fn handle_stream_window(&mut self, frame: &StreamWindow, emit: &mut impl FnMut(SessionEvent)) {
        let Some(stream) = self.state.streams.get_mut(&frame.stream_id) else {
            return;
        };

        let was_full = stream.send_capacity(self.config.stream_send_buffer_size) == 0;
        if frame.maximum_offset > stream.peer_max_offset {
            stream.peer_max_offset = frame.maximum_offset;
        }
        if was_full && stream.send_capacity(self.config.stream_send_buffer_size) > 0 {
            emit(SessionEvent::Writable(frame.stream_id));
        }
    }

    fn handle_stream_close(
        &mut self,
        frame: &StreamClose,
        emit: &mut impl FnMut(SessionEvent),
    ) -> Result<(), ()> {
        let mut created = false;
        let stream = match self.state.streams.entry(frame.stream_id) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                match classify_missing_stream(
                    self.config.local_parity,
                    self.state.next_stream_ordinal,
                    frame.stream_id,
                    &mut self.state.remote_stream_history,
                ) {
                    MissingStreamAction::Create => {}
                    MissingStreamAction::Ignore => return Ok(()),
                    MissingStreamAction::FailProtocol => {
                        self.fail_session(
                            SessionClose {
                                code: SessionCloseCode::PROTOCOL,
                            },
                            emit,
                        );
                        return Err(());
                    }
                }

                created = true;
                entry.insert(StreamState::new(
                    StreamRole::Responder,
                    self.config.stream_receive_buffer_size,
                    self.config.initial_peer_stream_receive_window,
                ))
            }
        };

        if created {
            emit(SessionEvent::Opened(frame.stream_id));
        }

        if Self::target_affects_inbound(stream.role, frame.target)
            && !matches!(
                stream.inbound_state,
                InboundState::Closed(_) | InboundState::Discarding
            )
        {
            stream.inbound_state = InboundState::Closed(frame.clone());
            stream.reset_recv();
            emit(SessionEvent::Closed(frame.clone()));
        }
        if Self::target_affects_outbound(stream.role, frame.target)
            && !matches!(stream.outbound_state, OutboundState::Closed)
        {
            stream.outbound_state = OutboundState::Closed;
            stream.tx.clear();
            stream.pending_close = None;
            emit(SessionEvent::WritableClosed(frame.stream_id));
        }
        self.try_reap_stream(frame.stream_id);
        Ok(())
    }

    fn handle_session_close(&mut self, close: SessionClose, emit: &mut impl FnMut(SessionEvent)) {
        if self.state.session_state == SessionState::Closed {
            return;
        }

        self.state.session_state = SessionState::Closed;
        self.state.tracked_records.clear();
        self.clear_streams();
        self.state.pending_control = Default::default();
        emit(SessionEvent::SessionClosed(close));
    }

    fn apply_local_close_to_stream(stream: &mut StreamState, target: CloseTarget) {
        if Self::target_affects_inbound(stream.role, target) {
            stream.inbound_state = InboundState::Discarding;
            stream.reset_recv();
        }
        if Self::target_affects_outbound(stream.role, target) {
            stream.outbound_state = OutboundState::Closed;
            stream.tx.clear();
        }
    }

    fn target_affects_inbound(role: StreamRole, target: CloseTarget) -> bool {
        matches!(target, CloseTarget::Both) || role.inbound_target() == target
    }

    fn target_affects_outbound(role: StreamRole, target: CloseTarget) -> bool {
        matches!(target, CloseTarget::Both) || role.outbound_target() == target
    }

    fn stream_is_reapable(&self, stream_id: StreamId, stream: &StreamState) -> bool {
        let tracked_refs_stream = self.state.tracked_records.values().any(|record| {
            record.window_updates.iter().any(|(id, _)| *id == stream_id)
                || record.frames.iter().any(|frame| match frame {
                    TrackedFrame::StreamData(frame) => frame.stream_id == stream_id,
                    TrackedFrame::StreamClose(frame) => frame.stream_id == stream_id,
                    TrackedFrame::Close(_) => false,
                })
        });
        if tracked_refs_stream {
            return false;
        }

        if !stream.tx.is_empty()
            || stream.pending_close.is_some()
            || stream.pending_window
            || stream.readable_bytes() > 0
            || stream.rx.buffered_end_offset() > stream.rx.start_offset()
        {
            return false;
        }

        matches!(
            stream.inbound_state,
            InboundState::Finished | InboundState::Closed(_) | InboundState::Discarding
        ) && matches!(
            stream.outbound_state,
            OutboundState::Finished | OutboundState::Closed
        )
    }

    fn reap_reapable_streams(&mut self) {
        let mut index = 0usize;
        while index < self.state.streams.len() {
            let stream_id = *self.state.streams.get_index(index).unwrap().0;
            let len_before = self.state.streams.len();
            self.try_reap_stream(stream_id);
            if self.state.streams.len() == len_before {
                index += 1;
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

    fn fail_session(&mut self, close: SessionClose, emit: &mut impl FnMut(SessionEvent)) {
        if self.state.session_state == SessionState::Closed {
            return;
        }

        self.state.session_state = SessionState::Closed;
        self.state.tracked_records.clear();
        self.state.pending_control = Default::default();
        self.state.pending_control.close = Some(close.clone());
        self.clear_streams();
        emit(SessionEvent::SessionClosed(close));
    }

    fn clear_streams(&mut self) {
        self.state.next_stream_index = 0;
        self.state.streams.clear();
    }
}

fn schedule_ack(ack_state: &mut AckState, due_at: Instant) {
    *ack_state = match *ack_state {
        AckState::Dirty { due_at: old } => AckState::Dirty {
            due_at: due_at.min(old),
        },
        AckState::Idle => AckState::Dirty { due_at },
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissingStreamAction {
    Create,
    Ignore,
    FailProtocol,
}

fn classify_missing_stream(
    local_parity: StreamParity,
    next_stream_ordinal: u32,
    stream_id: StreamId,
    remote_stream_history: &mut RemoteStreamHistory,
) -> MissingStreamAction {
    if !local_parity.remote().matches(stream_id) {
        return if local_stream_was_opened(local_parity, next_stream_ordinal, stream_id) {
            MissingStreamAction::Ignore
        } else {
            MissingStreamAction::FailProtocol
        };
    }

    if remote_stream_history.observe(stream_id) {
        MissingStreamAction::Ignore
    } else {
        MissingStreamAction::Create
    }
}

fn local_stream_was_opened(
    local_parity: StreamParity,
    next_stream_ordinal: u32,
    stream_id: StreamId,
) -> bool {
    local_parity.matches(stream_id)
        && stream_id.0 < local_parity.make_stream_id(next_stream_ordinal).0
}

fn restore_tracked_record(
    now: Instant,
    ack_state: &mut AckState,
    pending_control: &mut state::PendingSessionControl,
    streams: &mut IndexMap<StreamId, StreamState>,
    record: TrackedRecord,
) {
    if record.ack_included {
        schedule_ack(ack_state, now);
    }
    if record.ping_included {
        pending_control.ping = true;
    }
    for (stream_id, maximum_offset) in record.window_updates {
        if let Some(stream) = streams.get_mut(&stream_id) {
            if stream.recv_limit() >= maximum_offset {
                stream.pending_window = true;
            }
        }
    }
    for frame in record.frames {
        requeue_tracked_frame(pending_control, streams, frame);
    }
}

fn requeue_tracked_frame(
    pending_control: &mut state::PendingSessionControl,
    streams: &mut IndexMap<StreamId, StreamState>,
    frame: TrackedFrame,
) {
    match frame {
        TrackedFrame::Close(close) => {
            pending_control.close = Some(close);
        }
        TrackedFrame::StreamClose(close) => restore_stream_close(streams, close),
        TrackedFrame::StreamData(frame) => restore_stream_data(streams, frame),
    }
}

fn restore_stream_close(streams: &mut IndexMap<StreamId, StreamState>, close: StreamClose) {
    if let Some(stream) = streams.get_mut(&close.stream_id) {
        stream.pending_close = Some(close);
    }
}

fn restore_stream_data(streams: &mut IndexMap<StreamId, StreamState>, frame: TrackedStreamData) {
    if let Some(stream) = streams.get_mut(&frame.stream_id) {
        if matches!(stream.outbound_state, OutboundState::Closed) {
            return;
        }
        stream.tx.mark_lost(StreamTxRange {
            offset: frame.offset,
            len: frame.len,
            fin: frame.fin,
        });
        if frame.fin && matches!(stream.outbound_state, OutboundState::Finished) {
            stream.outbound_state = OutboundState::FinQueued;
        }
    }
}

fn acknowledge_tracked_frame(
    streams: &mut IndexMap<StreamId, StreamState>,
    stream_send_buffer_size: usize,
    frame: &TrackedFrame,
    emit: &mut impl FnMut(SessionEvent),
) {
    match frame {
        TrackedFrame::Close(_) | TrackedFrame::StreamClose(_) => {}
        TrackedFrame::StreamData(frame) => {
            let stream_id = frame.stream_id;
            if let Some(stream) = streams.get_mut(&stream_id) {
                let was_full = stream.send_capacity(stream_send_buffer_size) == 0;
                stream.tx.mark_acked(StreamTxRange {
                    offset: frame.offset,
                    len: frame.len,
                    fin: frame.fin,
                });
                if was_full && stream.send_capacity(stream_send_buffer_size) > 0 {
                    emit(SessionEvent::Writable(stream_id));
                }
            }
        }
    }
}
