pub use self::{stream_ops::*, stream_parity::*, stream_rx::*};

mod ack_tracker;
mod range_set;
mod remote_stream_history;
mod state;
mod stream_ops;
mod stream_parity;
mod stream_rx;
mod stream_tx;
mod tracked;

#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};

use bytes::Bytes;
use indexmap::IndexMap;
use ql_wire::{
    CloseTarget, RecordAck, RecordSeq, RouteId, SessionClose, SessionCloseCode, SessionFrame,
    SessionRecordBuilder, StreamClose, StreamData, StreamHeader, StreamId, StreamWindow, VarInt,
    WireError,
};

use self::{
    ack_tracker::{AckTracker, PendingAck, ReceiveOutcome},
    remote_stream_history::RemoteStreamHistory,
    state::{InboundState, OutboundState, SessionPhase, SessionState, StreamRole, StreamState},
    stream_tx::StreamTxRange,
    tracked::{TrackedFrame, TrackedRecord, TrackedStreamData},
};
use crate::{NoSessionError, StreamError};

#[derive(Debug, Clone, Copy)]
pub struct SessionConfig {
    pub local_parity: StreamParity,
    pub record_max_size: usize,
    pub ack_delay: Duration,
    pub retransmit_timeout: Duration,
    pub keepalive_interval: Duration,
    pub peer_timeout: Duration,
    pub stream_send_buffer_size: usize,
    pub stream_receive_buffer_size: u32,
    pub initial_peer_stream_receive_window: u32,
    pub accepted_record_window: u64,
    pub pending_ack_range_limit: usize,
}

impl Default for SessionConfig {
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
            accepted_record_window: 4096,
            pending_ack_range_limit: 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    Opened {
        stream_id: StreamId,
        route_id: RouteId,
    },
    Readable(StreamId),
    Writable(StreamId),
    Finished(StreamId),
    OutboundFinished(StreamId),
    Closed(StreamClose),
    WritableClosed(StreamClose),
    SessionClosed(SessionClose),
}

pub(crate) trait EventSink {
    fn emit(&mut self, event: SessionEvent);
}

impl<F> EventSink for F
where
    F: FnMut(SessionEvent),
{
    fn emit(&mut self, event: SessionEvent) {
        self(event);
    }
}

pub struct SessionFsm {
    config: SessionConfig,
    state: SessionState,
}

impl SessionFsm {
    pub fn new(mut config: SessionConfig, now: Instant) -> Self {
        config.record_max_size = config
            .record_max_size
            .max(SessionRecordBuilder::MIN_CAPACITY);
        config.stream_send_buffer_size = config.stream_send_buffer_size.max(1);
        config.stream_receive_buffer_size = config.stream_receive_buffer_size.max(1);
        config.accepted_record_window = config.accepted_record_window.max(1);
        config.pending_ack_range_limit = config.pending_ack_range_limit.max(1);
        Self {
            config,
            state: SessionState {
                last_activity_at: now,
                last_inbound_at: now,
                phase: SessionPhase::Open,
                next_stream_ordinal: 0,
                next_record_seq: RecordSeq::from_u32(0),
                next_write_id: 0,
                tracked_records: Default::default(),
                ack_tracker: AckTracker::new(
                    config.accepted_record_window,
                    config.pending_ack_range_limit,
                ),
                pending_ping: false,
                streams: Default::default(),
                next_stream_index: 0,
                remote_stream_history: RemoteStreamHistory::new(config.local_parity.remote()),
            },
        }
    }

    pub fn open_stream<E>(
        &mut self,
        route_id: RouteId,
        sink: E,
    ) -> Result<StreamOps<'_, E>, NoSessionError>
    where
        E: EventSink,
    {
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
                Some(route_id),
                self.config.stream_receive_buffer_size,
                self.config.initial_peer_stream_receive_window,
            ),
        );
        let stream_index = self.state.streams.len() - 1;
        Ok(StreamOps::new(self, stream_id, stream_index, sink))
    }

    pub fn stream<E>(
        &mut self,
        stream_id: StreamId,
        sink: E,
    ) -> Result<StreamOps<'_, E>, StreamError>
    where
        E: EventSink,
    {
        self.ensure_session_open()?;
        let Some(stream_index) = self.state.streams.get_index_of(&stream_id) else {
            return Err(StreamError::MissingStream);
        };

        Ok(StreamOps::new(self, stream_id, stream_index, sink))
    }

    pub fn queue_ping(&mut self) -> Result<(), NoSessionError> {
        self.ensure_session_open()?;
        self.state.pending_ping = true;
        Ok(())
    }

    pub(crate) fn close(&mut self, code: SessionCloseCode, sink: &mut impl EventSink) {
        if self.state.phase != SessionPhase::Open {
            return;
        }

        let close = SessionClose { code };
        self.state.phase = SessionPhase::Closing(close.clone());
        self.state.tracked_records.clear();
        self.state.ack_tracker.clear_ack_state();
        self.clear_streams();
        sink.emit(SessionEvent::SessionClosed(close));
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state.phase == SessionPhase::Closed
    }

    pub(crate) fn receive<I>(
        &mut self,
        now: Instant,
        seq: RecordSeq,
        frames: I,
        sink: &mut impl EventSink,
    ) where
        I: IntoIterator<Item = Result<SessionFrame<Bytes>, WireError>>,
    {
        self.state.last_activity_at = now;
        self.state.last_inbound_at = now;

        if self.state.phase != SessionPhase::Open {
            return;
        }

        self.collect_timeouts(now);

        match self.state.ack_tracker.insert(seq) {
            ReceiveOutcome::TooOld => return,
            ReceiveOutcome::Duplicate => {
                self.schedule_ack(now, true);
                return;
            }
            ReceiveOutcome::New => {}
        }

        let mut ack_eliciting = false;
        let mut handled_close = false;

        for frame in frames {
            let Ok(frame) = frame else {
                self.close(SessionCloseCode::PROTOCOL, sink);
                return;
            };
            ack_eliciting |= !matches!(frame, SessionFrame::Ack(_));
            match frame {
                SessionFrame::Ping => {}
                SessionFrame::Ack(ack) => self.process_record_ack(&ack, sink),
                SessionFrame::StreamData(frame) => {
                    if self.handle_stream_data(frame, sink).is_err() {
                        self.close(SessionCloseCode::PROTOCOL, sink);
                        return;
                    }
                }
                SessionFrame::StreamWindow(frame) => self.handle_stream_window(&frame, sink),
                SessionFrame::StreamClose(frame) => {
                    if self.handle_stream_close(&frame, sink).is_err() {
                        self.close(SessionCloseCode::PROTOCOL, sink);
                        return;
                    }
                }
                SessionFrame::Close(close) => {
                    self.close(close.code, sink);
                    handled_close = true;
                    break;
                }
            }
        }

        if handled_close {
            return;
        }

        if ack_eliciting {
            self.schedule_ack(now, false);
        }
    }

    pub fn complete_write(&mut self, now: Instant, write_id: u64, success: bool) {
        if !self.state.phase.is_open() {
            return;
        }
        if success {
            let Some(record) = self.state.tracked_records.get_mut(&write_id) else {
                return;
            };
            if record.sent_at.is_some() {
                return;
            }
            self.state.last_activity_at = now;
            record.sent_at = Some(now);
        } else {
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
                now,
                &mut self.state.ack_tracker,
                &mut self.state.pending_ping,
                &mut self.state.streams,
                record,
            );
        }
    }

    pub fn on_timer(&mut self, now: Instant, sink: &mut impl EventSink) {
        if !self.state.phase.is_open() {
            return;
        }
        self.collect_timeouts(now);
        if !self.config.peer_timeout.is_zero()
            && self.state.last_inbound_at + self.config.peer_timeout <= now
        {
            self.close(SessionCloseCode::TIMEOUT, sink);
            return;
        }
        if self.state.phase == SessionPhase::Open
            && !self.config.keepalive_interval.is_zero()
            && self.state.last_activity_at + self.config.keepalive_interval <= now
        {
            self.state.pending_ping = true;
        }
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        if !self.state.phase.is_open() {
            return None;
        }
        let ack_deadline = self.state.ack_tracker.ack_deadline();
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
        let is_open = self.state.phase.is_open();
        let keepalive_deadline =
            (is_open && !self.config.keepalive_interval.is_zero() && !self.state.pending_ping)
                .then_some(self.state.last_activity_at + self.config.keepalive_interval);
        let peer_timeout_deadline = (is_open && !self.config.peer_timeout.is_zero())
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

    pub fn has_shutdown_work(&self) -> bool {
        self.state.ack_tracker.ack_deadline().is_some() || !self.state.tracked_records.is_empty()
    }

    pub fn take_next_write(&mut self, now: Instant) -> Option<(Option<u64>, SessionRecordBuilder)> {
        match &self.state.phase {
            SessionPhase::Closing(close) => {
                let seq = self.state.next_record_seq;
                next_seq(&mut self.state.next_record_seq);
                let mut builder = SessionRecordBuilder::new(seq, self.config.record_max_size);
                assert!(builder.push_close(close), "builder has capacity");
                self.state.phase = SessionPhase::Closed;
                return Some((None, builder));
            }
            SessionPhase::Closed => {
                return None;
            }
            SessionPhase::Open => {}
        }
        self.collect_timeouts(now);

        let (builder, outbound) = self.build_next_record(now)?;

        let should_track = outbound.ping_included
            || !outbound.window_updates.is_empty()
            || !outbound.frames.is_empty();
        let write_id = should_track.then(|| {
            let write_id = self.state.next_write_id;
            self.state.next_write_id = self.state.next_write_id.wrapping_add(1);
            self.state.tracked_records.insert(write_id, outbound);
            write_id
        });

        Some((write_id, builder))
    }

    fn build_next_record(&mut self, now: Instant) -> Option<(SessionRecordBuilder, TrackedRecord)> {
        let seq = self.state.next_record_seq;
        let mut builder = SessionRecordBuilder::new(seq, self.config.record_max_size);
        let mut outbound = TrackedRecord {
            seq,
            frames: Vec::new(),
            ack: None,
            ping_included: false,
            window_updates: Vec::new(),
            sent_at: None,
        };

        self.push_next_pending_stream_close(&mut builder, &mut outbound);

        if self.state.pending_ping && builder.push_ping() {
            self.state.pending_ping = false;
            outbound.ping_included = true;
        }

        self.push_next_pending_stream_window(&mut builder, &mut outbound);

        self.push_next_stream_data(&mut builder, &mut outbound);

        if let Some(pending_ack) = self.pending_ack(builder.remaining_capacity()) {
            if (!builder.is_empty() || pending_ack.due_at <= now)
                && builder.push_ack(&pending_ack.ack)
            {
                self.state.ack_tracker.on_ack_emitted(&pending_ack);
                outbound.ack = Some(pending_ack.ack);
            }
        }

        if builder.is_empty() {
            return None;
        }

        next_seq(&mut self.state.next_record_seq);
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
                maximum_offset: VarInt::from_u64(stream.recv_limit()).unwrap(),
            };
            if !builder.push_stream_window(&frame) {
                break;
            }

            stream.pending_window = false;
            stream.advertised_max_offset = frame.maximum_offset.into_inner();
            outbound
                .window_updates
                .push((stream_id, frame.maximum_offset.into_inner()));
        }
    }

    fn push_next_stream_data(
        &mut self,
        builder: &mut SessionRecordBuilder,
        outbound: &mut TrackedRecord,
    ) {
        const OVERHEAD: usize = 1 + StreamData::<Vec<u8>>::MIN_WIRE_SIZE;

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
            let Some(candidate) = stream.tx.poll_transmit(max_payload, stream.peer_max_offset)
            else {
                continue;
            };
            let offset =
                VarInt::from_u64(candidate.offset).expect("stream offsets must fit ql-wire varint");
            let frame = StreamData {
                stream_id,
                offset,
                header: if matches!(stream.role, StreamRole::Initiator) && candidate.offset == 0 {
                    stream.route_id.map(|route_id| StreamHeader { route_id })
                } else {
                    None
                },
                fin: candidate.fin,
                bytes: stream.tx.ranged_bytes(candidate),
            };
            let res = builder.push_stream_data(&frame);
            assert!(res, "builder has capacity");

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

    fn ensure_session_open(&self) -> Result<(), NoSessionError> {
        if self.state.phase == SessionPhase::Open {
            Ok(())
        } else {
            Err(NoSessionError)
        }
    }

    fn process_record_ack(&mut self, ack: &RecordAck, sink: &mut impl EventSink) {
        let stream_send_buffer_size = self.config.stream_send_buffer_size;
        let acked_records = self
            .state
            .tracked_records
            .extract_if(.., |_, record| {
                record.sent_at.is_some() && ack.contains(record.seq.into_inner())
            })
            .map(|(_, record)| record)
            .collect::<Vec<_>>();

        for record in acked_records {
            for frame in &record.frames {
                acknowledge_tracked_frame(
                    &mut self.state.streams,
                    stream_send_buffer_size,
                    frame,
                    sink,
                );
            }
        }
        self.reap_reapable_streams();
    }

    fn schedule_ack(&mut self, now: Instant, immediate: bool) {
        self.state.ack_tracker.schedule_ack(if immediate {
            now
        } else {
            now + self.config.ack_delay
        });
    }

    fn pending_ack(&self, remaining_capacity: usize) -> Option<PendingAck> {
        let max_ack_wire_size = remaining_capacity.checked_sub(1)?;
        self.state.ack_tracker.pending_ack(max_ack_wire_size)
    }

    fn collect_timeouts(&mut self, now: Instant) {
        let retransmit_timeout = self.config.retransmit_timeout;
        for (_, record) in self.state.tracked_records.extract_if(.., |_, record| {
            record
                .sent_at
                .is_some_and(|sent_at| sent_at + retransmit_timeout <= now)
        }) {
            restore_tracked_record(
                now,
                &mut self.state.ack_tracker,
                &mut self.state.pending_ping,
                &mut self.state.streams,
                record,
            );
        }
    }

    fn handle_stream_data(
        &mut self,
        frame: StreamData<Bytes>,
        sink: &mut impl EventSink,
    ) -> Result<(), ()> {
        let StreamData {
            stream_id,
            offset,
            header,
            fin,
            bytes,
        } = frame;
        let stream = match self.state.streams.get_mut(&stream_id) {
            Some(stream) => stream,
            None => match self.create_remote_stream(stream_id)? {
                Some(stream) => stream,
                None => return Ok(()),
            },
        };

        let frame_offset = offset.into_inner();
        let Some(frame_end) = frame_offset.checked_add(bytes.len() as u64) else {
            return Err(());
        };
        let readable_before = stream.readable_bytes();
        let was_finished = matches!(stream.inbound_state, InboundState::Finished);

        let opened_route = match (stream.role, stream.route_id, header, frame_offset) {
            (StreamRole::Responder, None, Some(header), 0) => {
                stream.route_id = Some(header.route_id);
                Some(header.route_id)
            }
            (StreamRole::Initiator, _, Some(_), _)
            | (StreamRole::Responder, None, Some(_), _)
            | (StreamRole::Responder, None, None, 0) => return Err(()),
            _ => None,
        };

        match stream.inbound_state {
            InboundState::Open => {}
            InboundState::Discarding | InboundState::Closed(_) => return Ok(()),
            InboundState::Finished => {
                // finished stream should always have a final offset
                let Some(final_offset) = stream.rx.final_offset() else {
                    debug_assert!(false, "finished stream must retain final offset");
                    return Ok(());
                };

                // retransmitted data for an already-finished stream is fine as long as it stays
                // within the finalized byte range and any repeated FIN lands on that same offset.
                if (!frame.fin || frame_end == final_offset) && frame_end <= final_offset {
                    if let Some(route_id) = opened_route {
                        sink.emit(SessionEvent::Opened {
                            stream_id,
                            route_id,
                        });
                        if readable_before > 0 {
                            sink.emit(SessionEvent::Readable(stream_id));
                        } else {
                            sink.emit(SessionEvent::Finished(stream_id));
                        }
                    }
                    return Ok(());
                }

                return Err(());
            }
        }

        let outcome = stream.rx.insert(frame_offset, fin, bytes).map_err(|_| ())?;

        if outcome.became_complete {
            stream.inbound_state = InboundState::Finished;
        }

        if let Some(route_id) = opened_route {
            sink.emit(SessionEvent::Opened {
                stream_id,
                route_id,
            });
        }

        if stream.route_id.is_some() && readable_before == 0 && stream.readable_bytes() > 0 {
            sink.emit(SessionEvent::Readable(stream_id));
        }

        if stream.route_id.is_some()
            && !was_finished
            && matches!(stream.inbound_state, InboundState::Finished)
            && stream.readable_bytes() == 0
        {
            sink.emit(SessionEvent::Finished(stream_id));
        }

        self.try_reap_stream(stream_id);
        Ok(())
    }

    fn handle_stream_window(&mut self, frame: &StreamWindow, sink: &mut impl EventSink) {
        let Some(stream) = self.state.streams.get_mut(&frame.stream_id) else {
            return;
        };

        let was_full = stream.send_capacity(self.config.stream_send_buffer_size) == 0;
        let maximum_offset = frame.maximum_offset.into_inner();
        if maximum_offset > stream.peer_max_offset {
            stream.peer_max_offset = maximum_offset;
        }
        if was_full && stream.send_capacity(self.config.stream_send_buffer_size) > 0 {
            sink.emit(SessionEvent::Writable(frame.stream_id));
        }
    }

    fn handle_stream_close(
        &mut self,
        frame: &StreamClose,
        sink: &mut impl EventSink,
    ) -> Result<(), ()> {
        let stream_id = frame.stream_id;
        let stream = match self.state.streams.get_mut(&stream_id) {
            Some(stream) => stream,
            None => match self.create_remote_stream(stream_id)? {
                Some(stream) => stream,
                None => return Ok(()),
            },
        };

        if Self::target_affects_inbound(stream.role, frame.target)
            && !matches!(
                stream.inbound_state,
                InboundState::Closed(_) | InboundState::Discarding
            )
        {
            stream.inbound_state = InboundState::Closed(frame.clone());
            stream.reset_recv();
            sink.emit(SessionEvent::Closed(frame.clone()));
        }
        if Self::target_affects_outbound(stream.role, frame.target)
            && !matches!(stream.outbound_state, OutboundState::Closed)
        {
            stream.outbound_state = OutboundState::Closed;
            stream.tx.clear();
            stream.pending_close = None;
            sink.emit(SessionEvent::WritableClosed(frame.clone()));
        }
        self.try_reap_stream(frame.stream_id);
        Ok(())
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
        let Some(index) = self.state.streams.get_index_of(&stream_id) else {
            return;
        };
        self.try_reap_stream_at(stream_id, index);
    }

    fn try_reap_stream_at(&mut self, stream_id: StreamId, index: usize) {
        let Some((indexed_stream_id, stream)) = self.state.streams.get_index(index) else {
            return;
        };
        debug_assert_eq!(*indexed_stream_id, stream_id);
        if !self.stream_is_reapable(stream_id, stream) {
            return;
        }
        self.reap_stream_at(index);
    }

    fn reap_stream_at(&mut self, index: usize) {
        self.state.streams.shift_remove_index(index);

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

    fn clear_streams(&mut self) {
        self.state.next_stream_index = 0;
        self.state.streams.clear();
    }

    fn create_remote_stream(
        &mut self,
        stream_id: StreamId,
    ) -> Result<Option<&mut StreamState>, ()> {
        match classify_missing_stream(
            self.config.local_parity,
            self.state.next_stream_ordinal,
            stream_id,
            &mut self.state.remote_stream_history,
        ) {
            MissingStreamAction::Create => {}
            MissingStreamAction::Ignore => return Ok(None),
            MissingStreamAction::FailProtocol => {
                return Err(());
            }
        }

        let stream = self
            .state
            .streams
            .entry(stream_id)
            .insert_entry(StreamState::new(
                StreamRole::Responder,
                None,
                self.config.stream_receive_buffer_size,
                self.config.initial_peer_stream_receive_window,
            ));

        Ok(Some(stream.into_mut()))
    }
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
        && stream_id.into_inner()
            < local_parity
                .make_stream_id(next_stream_ordinal)
                .into_inner()
}

fn restore_tracked_record(
    now: Instant,
    ack_tracker: &mut AckTracker,
    pending_ping: &mut bool,
    streams: &mut IndexMap<StreamId, StreamState>,
    record: TrackedRecord,
) {
    if let Some(ack) = &record.ack {
        ack_tracker.restore_acked_ranges(ack, now);
    }
    if record.ping_included {
        *pending_ping = true;
    }
    for (stream_id, maximum_offset) in record.window_updates {
        if let Some(stream) = streams.get_mut(&stream_id) {
            if stream.recv_limit() >= maximum_offset {
                stream.pending_window = true;
            }
        }
    }
    for frame in record.frames {
        requeue_tracked_frame(streams, frame);
    }
}

fn requeue_tracked_frame(streams: &mut IndexMap<StreamId, StreamState>, frame: TrackedFrame) {
    match frame {
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
        stream.tx.retransmit(stream_tx::StreamTxRange {
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
    sink: &mut impl EventSink,
) {
    match frame {
        TrackedFrame::StreamClose(_) => {}
        TrackedFrame::StreamData(frame) => {
            let stream_id = frame.stream_id;
            if let Some(stream) = streams.get_mut(&stream_id) {
                let was_full = stream.send_capacity(stream_send_buffer_size) == 0;
                let had_unacked_fin = frame.fin && stream.tx.has_unacked_fin();
                stream.tx.ack(StreamTxRange {
                    offset: frame.offset,
                    len: frame.len,
                    fin: frame.fin,
                });
                if was_full && stream.send_capacity(stream_send_buffer_size) > 0 {
                    sink.emit(SessionEvent::Writable(stream_id));
                }
                if had_unacked_fin && !stream.tx.has_unacked_fin() {
                    sink.emit(SessionEvent::OutboundFinished(stream_id));
                }
            }
        }
    }
}

#[inline]
#[track_caller]
fn next_seq(seq: &mut RecordSeq) {
    *seq = seq
        .into_inner()
        .checked_add(1)
        .and_then(|next| RecordSeq::from_u64(next).ok())
        .expect("record sequence overflow");
}
