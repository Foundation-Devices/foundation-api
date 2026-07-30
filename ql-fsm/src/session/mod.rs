pub use self::{state::TerminalFrame, stream_ops::*, stream_parity::*, stream_rx::*};

mod ack_tracker;
mod range_set;
mod remote_stream_history;
mod replay_window;
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
use ql_codec::Varint;
use ql_common::StreamId;
use ql_wire::{
    RecordAck, RecordSeq, ResetTarget, SessionClose, SessionCloseCode, SessionFrame,
    SessionRecordBuilder, StreamData, StreamReset, StreamWindow,
};

use self::{
    ack_tracker::{AckTracker, PendingAck},
    remote_stream_history::RemoteStreamHistory,
    replay_window::ReplayWindow,
    state::{InboundState, OutboundState, SessionPhase, SessionState, StreamRole, StreamState},
    stream_tx::StreamTxRange,
    tracked::{LossRecovery, TrackedFrame, TrackedRecord, TrackedStreamData},
};
use crate::{NoSessionError, StreamError, StreamResetEvent, StreamResetTarget};

#[derive(Debug, Clone, Copy)]
pub struct SessionConfig {
    /// maximum total wire size for one session record, including header and auth tag
    pub record_max_size: usize,
    /// delay before sending a pure record ack
    pub ack_delay: Duration,
    /// initial wait before resending unacked session records
    pub retransmit_timeout: Duration,
    /// idle delay before sending a keepalive ping
    pub keepalive_interval: Duration,
    /// how long to wait before declaring the peer dead
    pub peer_timeout: Duration,
    /// maximum bytes buffered locally for one stream send side
    pub stream_send_buffer_size: usize,
    /// maximum bytes buffered locally for one stream receive side
    pub stream_receive_buffer_size: u32,
    /// how many accepted record sequence numbers to retain for replay detection
    pub accepted_record_window: u64,
    /// maximum disjoint pending ACK ranges to retain before dropping the oldest low ranges
    pub pending_ack_range_limit: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            record_max_size: 8 * 1024,
            ack_delay: Duration::from_millis(5),
            retransmit_timeout: Duration::from_secs(1),
            keepalive_interval: Duration::from_secs(10),
            peer_timeout: Duration::from_secs(30),
            stream_send_buffer_size: 16 * 1024,
            stream_receive_buffer_size: 16 * 1024,
            accepted_record_window: 4096,
            pending_ack_range_limit: 64,
        }
    }
}

/// per-session values settled by the handshake
#[derive(Debug, Clone, Copy)]
pub struct SessionParams {
    pub local_parity: StreamParity,
    pub initial_stream_receive_window: u32,
}

impl Default for SessionParams {
    fn default() -> Self {
        Self {
            local_parity: StreamParity::Even,
            initial_stream_receive_window: 16 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    Opened(StreamId),
    Readable(StreamId),
    Writable(StreamId),
    Finished(StreamId),
    OutboundFinished(StreamId),
    Reset(StreamResetEvent),
    SessionClosed(SessionClose),
    Unpaired,
}

pub trait EventSink {
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
    params: SessionParams,
    state: SessionState,
}

impl SessionFsm {
    pub fn new(mut config: SessionConfig, params: SessionParams, now: Instant) -> Self {
        config.record_max_size = config
            .record_max_size
            .max(SessionRecordBuilder::MIN_CAPACITY);
        config.stream_send_buffer_size = config.stream_send_buffer_size.max(1);
        config.stream_receive_buffer_size = config.stream_receive_buffer_size.max(1);
        Self {
            config,
            params,
            state: SessionState {
                last_activity_at: now,
                last_inbound_at: now,
                phase: SessionPhase::Open,
                next_stream_ordinal: 0,
                next_record_seq: RecordSeq(0),
                next_write_id: 0,
                tracked_records: IndexMap::default(),
                loss_recovery: LossRecovery::new(config.retransmit_timeout),
                replay_window: ReplayWindow::new(config.accepted_record_window),
                ack_tracker: AckTracker::new(config.pending_ack_range_limit),
                pending_ping: false,
                streams: IndexMap::default(),
                next_stream_id: None,
                remote_stream_history: RemoteStreamHistory::new(params.local_parity.remote()),
            },
        }
    }

    pub fn open_stream<E>(
        &mut self,
        header: Box<[u8]>,
        sink: E,
    ) -> Result<StreamOps<'_, E>, NoSessionError>
    where
        E: EventSink,
    {
        self.ensure_session_open()?;
        let stream_id = self
            .params
            .local_parity
            .make_stream_id(self.state.next_stream_ordinal);
        self.state.next_stream_ordinal = self.state.next_stream_ordinal.saturating_add(1);
        self.state.streams.insert(
            stream_id,
            StreamState::new(
                StreamRole::Initiator,
                Some(Bytes::from(header)),
                self.config.stream_receive_buffer_size,
                self.params.initial_stream_receive_window,
            ),
        );
        Ok(StreamOps::new(self, stream_id, sink))
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
        // Event::Opened only fires after we receive the first frame of a stream
        // prevent early access to streams
        if self
            .state
            .streams
            .get(&stream_id)
            .and_then(|stream| stream.header.as_ref())
            .is_none()
        {
            return Err(StreamError::MissingStream);
        }
        Ok(StreamOps::new(self, stream_id, sink))
    }

    pub fn queue_ping(&mut self) -> Result<(), NoSessionError> {
        self.ensure_session_open()?;
        self.state.pending_ping = true;
        Ok(())
    }

    pub fn close(&mut self, code: SessionCloseCode, sink: &mut impl EventSink) {
        if self.state.phase != SessionPhase::Open {
            return;
        }

        self.begin_termination(TerminalFrame::Close(SessionClose { code }), sink);
    }

    pub fn unpair(&mut self, sink: &mut impl EventSink) {
        if self.state.phase != SessionPhase::Open {
            return;
        }

        self.begin_termination(TerminalFrame::Unpair, sink);
    }

    pub fn is_closed(&self) -> bool {
        self.state.phase == SessionPhase::Closed
    }

    pub fn is_replay(&self, seq: RecordSeq) -> bool {
        self.state.replay_window.is_replay(seq)
    }

    pub fn receive<I>(&mut self, now: Instant, seq: RecordSeq, frames: I, sink: &mut impl EventSink)
    where
        I: IntoIterator<Item = Result<SessionFrame<Bytes>, ql_wire::Error>>,
    {
        if self.state.phase != SessionPhase::Open {
            return;
        }

        self.collect_timeouts(now);

        self.state.replay_window.accept(seq);
        self.state.ack_tracker.push(seq);

        self.state.last_activity_at = now;
        self.state.last_inbound_at = now;

        let mut ack_eliciting = false;

        for frame in frames {
            let Ok(frame) = frame else {
                self.close(SessionCloseCode::PROTOCOL, sink);
                return;
            };
            ack_eliciting |= !matches!(frame, SessionFrame::Ack(_));
            match frame {
                SessionFrame::Ping => {}
                SessionFrame::Unpair => {
                    self.unpair(sink);
                    return;
                }
                SessionFrame::Ack(ack) => self.process_record_ack(now, &ack, sink),
                SessionFrame::StreamData(frame) => {
                    if self.handle_stream_data(frame, sink).is_err() {
                        self.close(SessionCloseCode::PROTOCOL, sink);
                        return;
                    }
                }
                SessionFrame::StreamWindow(frame) => self.handle_stream_window(&frame),
                SessionFrame::StreamReset(frame) => {
                    if self.handle_stream_reset(&frame, sink).is_err() {
                        self.close(SessionCloseCode::PROTOCOL, sink);
                        return;
                    }
                }
                SessionFrame::Close(close) => {
                    self.close(close.code, sink);
                    return;
                }
            }
        }

        if ack_eliciting {
            self.schedule_ack(now);
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
            self.state.restore_tracked_record(now, &record);
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
        let rto = self.state.loss_recovery.rto();
        let retransmit_deadline = self
            .state
            .tracked_records
            .values()
            .filter_map(|record| record.sent_at.map(|sent_at| sent_at + rto))
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
        matches!(self.state.phase, SessionPhase::Terminating(_))
            || self.state.ack_tracker.ack_deadline().is_some()
            || !self.state.tracked_records.is_empty()
    }

    pub fn take_next_write(&mut self, now: Instant) -> Option<(Option<u64>, SessionRecordBuilder)> {
        const TRACKED_RECORD_LIMIT: usize = 64;

        match &self.state.phase {
            SessionPhase::Terminating(frame) => {
                let seq = self.state.next_record_seq;
                next_seq(&mut self.state.next_record_seq);
                let mut builder = SessionRecordBuilder::new(seq, self.config.record_max_size);
                match frame {
                    TerminalFrame::Close(close) => {
                        assert!(builder.push_close(close), "builder has capacity");
                    }
                    TerminalFrame::Unpair => {
                        assert!(builder.push_unpair(), "builder has capacity");
                    }
                }
                self.state.phase = SessionPhase::Closed;
                return Some((None, builder));
            }
            SessionPhase::Closed => {
                return None;
            }
            SessionPhase::Open => {}
        }
        self.collect_timeouts(now);

        // ack-only records need no tracking slot and prevent two full peers from stalling
        if self.state.tracked_records.len() >= TRACKED_RECORD_LIMIT {
            let seq = self.state.next_record_seq;
            let mut builder = SessionRecordBuilder::new(seq, self.config.record_max_size);
            let pending_ack = self.pending_ack(builder.remaining_capacity())?;
            if pending_ack.due_at > now || !builder.push_ack(&pending_ack.ack) {
                return None;
            }
            self.state.ack_tracker.on_ack_emitted(&pending_ack);
            next_seq(&mut self.state.next_record_seq);
            return Some((None, builder));
        }

        let (builder, outbound) = self.build_next_record(now)?;

        let should_track = !outbound.frames.is_empty();
        let write_id = should_track.then(|| {
            debug_assert!(self.state.tracked_records.len() < TRACKED_RECORD_LIMIT);
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
            sent_at: None,
        };

        self.push_next_pending_stream_reset(&mut builder, &mut outbound);

        if self.state.pending_ping && builder.push_ping() {
            self.state.pending_ping = false;
            outbound.frames.push(TrackedFrame::Ping);
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

    fn begin_termination(&mut self, frame: TerminalFrame, sink: &mut impl EventSink) {
        match &frame {
            TerminalFrame::Close(close) => sink.emit(SessionEvent::SessionClosed(close.clone())),
            TerminalFrame::Unpair => sink.emit(SessionEvent::Unpaired),
        }

        self.state.phase = SessionPhase::Terminating(frame);
        self.state.tracked_records.clear();
        self.state.ack_tracker.clear_ack_state();
        self.clear_streams();
    }

    fn push_next_pending_stream_reset(
        &mut self,
        builder: &mut SessionRecordBuilder,
        outbound: &mut TrackedRecord,
    ) {
        let len = self.state.streams.len();
        if len == 0 {
            return;
        }

        let start = self.state.round_robin_start();
        for offset in 0..len {
            let index = (start + offset) % len;
            let stream = self.state.streams.get_index_mut(index).unwrap().1;
            let Some(reset) = stream.pending_reset.as_ref() else {
                continue;
            };
            if !builder.push_stream_reset(reset) {
                break;
            }

            outbound.frames.push(TrackedFrame::StreamReset(
                stream.pending_reset.take().unwrap(),
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

        let start = self.state.round_robin_start();
        for offset in 0..len {
            let index = (start + offset) % len;
            let (&stream_id, stream) = self.state.streams.get_index_mut(index).unwrap();
            if !stream.pending_window {
                continue;
            }
            let frame = StreamWindow {
                stream_id,
                maximum_offset: Varint(stream.recv_limit()),
            };
            if !builder.push_stream_window(&frame) {
                break;
            }

            stream.pending_window = false;
            stream.advertised_max_offset = *frame.maximum_offset;
            outbound
                .frames
                .push(TrackedFrame::StreamWindow(stream_id, *frame.maximum_offset));
        }
    }

    fn push_next_stream_data(
        &mut self,
        builder: &mut SessionRecordBuilder,
        outbound: &mut TrackedRecord,
    ) {
        const OVERHEAD: usize = 1 + StreamData::<Vec<u8>>::MAX_WIRE_OVERHEAD;

        let len = self.state.streams.len();
        if len == 0 {
            return;
        }

        let start = self.state.round_robin_start();
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
            // The header shares the frame with the payload, so it has to come out of the same
            // budget, and that budget is set before poll_transmit picks the range.
            let header = match stream.role {
                StreamRole::Initiator if stream.tx.can_send_header() => stream.header.as_deref(),
                _ => None,
            };
            let Some(max_payload) = max_payload.checked_sub(header.map_or(0, <[u8]>::len)) else {
                continue;
            };
            let Some(candidate) = stream.tx.poll_transmit(max_payload, stream.peer_max_offset)
            else {
                continue;
            };
            let frame = StreamData {
                stream_id,
                offset: Varint(candidate.offset),
                header: if candidate.offset == 0 { header } else { None },
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

        self.state.set_round_robin_start(next_index);
    }

    fn ensure_session_open(&self) -> Result<(), NoSessionError> {
        if self.state.phase == SessionPhase::Open {
            Ok(())
        } else {
            Err(NoSessionError)
        }
    }

    fn process_record_ack(&mut self, now: Instant, ack: &RecordAck, sink: &mut impl EventSink) {
        let stream_send_buffer_size = self.config.stream_send_buffer_size;
        let mut latest_sent_at = None;
        let state = &mut self.state;
        for (_, record) in state
            .tracked_records
            .extract_if(.., |_, record| ack.contains(record.seq.0))
        {
            latest_sent_at = latest_sent_at.max(record.sent_at);
            for frame in &record.frames {
                acknowledge_tracked_frame(&mut state.streams, stream_send_buffer_size, frame, sink);
            }
        }
        if let Some(sent_at) = latest_sent_at {
            state
                .loss_recovery
                .on_ack(now.saturating_duration_since(sent_at));
        }
        self.reap_reapable_streams();
    }

    fn schedule_ack(&mut self, now: Instant) {
        self.state
            .ack_tracker
            .schedule_ack(now + self.config.ack_delay);
    }

    fn pending_ack(&self, remaining_capacity: usize) -> Option<PendingAck> {
        let max_ack_wire_size = remaining_capacity.checked_sub(1)?;
        self.state.ack_tracker.pending_ack(max_ack_wire_size)
    }

    fn collect_timeouts(&mut self, now: Instant) {
        let rto = self.state.loss_recovery.rto();
        let timed_out: Vec<_> = self
            .state
            .tracked_records
            .extract_if(.., |_, record| {
                record.sent_at.is_some_and(|sent_at| sent_at + rto <= now)
            })
            .map(|(_, record)| record)
            .collect();
        for record in &timed_out {
            self.state.restore_tracked_record(now, record);
        }
        if !timed_out.is_empty() {
            self.state.loss_recovery.on_timeout();
        }
        self.reap_reapable_streams();
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

        let frame_offset = *offset;
        let Some(frame_end) = frame_offset.checked_add(bytes.len() as u64) else {
            return Err(());
        };
        let readable_before = stream.readable_bytes();
        let was_finished = matches!(stream.inbound_state, InboundState::Finished);

        let opened = match (stream.role, stream.header.as_ref(), header, frame_offset) {
            (StreamRole::Responder, None, Some(header), 0) => {
                stream.header = Some(header);
                true
            }
            (StreamRole::Initiator, _, Some(_), _)
            | (StreamRole::Responder, None, Some(_), _)
            | (StreamRole::Responder, None, None, 0) => return Err(()),
            _ => false,
        };

        match stream.inbound_state {
            InboundState::Open => {}
            InboundState::Discarding | InboundState::Reset(_) => return Ok(()),
            InboundState::Finished => {
                // finished stream should always have a final offset
                let Some(final_offset) = stream.rx.final_offset() else {
                    debug_assert!(false, "finished stream must retain final offset");
                    return Ok(());
                };

                // retransmitted data for an already-finished stream is fine as long as it stays
                // within the finalized byte range and any repeated FIN lands on that same offset.
                if (!frame.fin || frame_end == final_offset) && frame_end <= final_offset {
                    if opened {
                        sink.emit(SessionEvent::Opened(stream_id));
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

        if opened {
            sink.emit(SessionEvent::Opened(stream_id));
        }

        if stream.header.is_some() && readable_before == 0 && stream.readable_bytes() > 0 {
            sink.emit(SessionEvent::Readable(stream_id));
        }

        if stream.header.is_some()
            && !was_finished
            && matches!(stream.inbound_state, InboundState::Finished)
            && stream.readable_bytes() == 0
        {
            sink.emit(SessionEvent::Finished(stream_id));
        }

        // Drop it here, or a later frame in this record fails as a protocol error instead of
        // being ignored.
        self.try_reap_stream(stream_id);
        Ok(())
    }

    fn handle_stream_window(&mut self, frame: &StreamWindow) {
        let Some(stream) = self.state.streams.get_mut(&frame.stream_id) else {
            return;
        };

        let maximum_offset = *frame.maximum_offset;
        if maximum_offset > stream.peer_max_offset {
            stream.peer_max_offset = maximum_offset;
        }
    }

    fn handle_stream_reset(
        &mut self,
        frame: &StreamReset,
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

        let inbound = Self::target_affects_inbound(stream.role, frame.target)
            && !matches!(
                stream.inbound_state,
                InboundState::Reset(_) | InboundState::Discarding
            );
        let outbound = Self::target_affects_outbound(stream.role, frame.target)
            && !matches!(stream.outbound_state, OutboundState::Closed);

        if inbound {
            stream.inbound_state = InboundState::Reset(frame.clone());
            stream.reset_recv();
        }
        if outbound {
            stream.outbound_state = OutboundState::Closed;
            stream.tx.clear();
            stream.pending_reset = None;
        }
        if inbound || outbound {
            let target = match (inbound, outbound) {
                (true, true) => StreamResetTarget::Both,
                (true, false) => StreamResetTarget::Reader,
                (false, true) => StreamResetTarget::Writer,
                (false, false) => unreachable!(),
            };
            sink.emit(SessionEvent::Reset(StreamResetEvent {
                stream_id,
                code: frame.code,
                target,
            }));
        }
        // Drop it here, or a later frame in this record fails as a protocol error instead of
        // being ignored.
        self.try_reap_stream(frame.stream_id);
        Ok(())
    }

    fn apply_local_reset_to_stream(stream: &mut StreamState, target: ResetTarget) {
        if Self::target_affects_inbound(stream.role, target) {
            stream.inbound_state = InboundState::Discarding;
            stream.reset_recv();
        }
        if Self::target_affects_outbound(stream.role, target) {
            stream.outbound_state = OutboundState::Closed;
            stream.tx.clear();
        }
    }

    fn target_affects_inbound(role: StreamRole, target: ResetTarget) -> bool {
        matches!(target, ResetTarget::Both) || role.inbound_target() == target
    }

    fn target_affects_outbound(role: StreamRole, target: ResetTarget) -> bool {
        matches!(target, ResetTarget::Both) || role.outbound_target() == target
    }

    fn reap_reapable_streams(&mut self) {
        let SessionState {
            tracked_records,
            streams,
            ..
        } = &mut self.state;
        streams
            .retain(|&stream_id, stream| !stream_is_reapable(tracked_records, stream_id, stream));
    }

    fn try_reap_stream(&mut self, stream_id: StreamId) {
        let reapable = self.state.streams.get(&stream_id).is_some_and(|stream| {
            stream_is_reapable(&self.state.tracked_records, stream_id, stream)
        });
        if reapable {
            self.state.streams.shift_remove(&stream_id);
        }
    }

    fn clear_streams(&mut self) {
        self.state.next_stream_id = None;
        self.state.streams.clear();
    }

    fn create_remote_stream(
        &mut self,
        stream_id: StreamId,
    ) -> Result<Option<&mut StreamState>, ()> {
        match classify_missing_stream(
            self.params.local_parity,
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
                self.params.initial_stream_receive_window,
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
        && stream_id.0 < local_parity.make_stream_id(next_stream_ordinal).0
}

fn stream_is_reapable(
    tracked_records: &IndexMap<u64, TrackedRecord>,
    stream_id: StreamId,
    stream: &StreamState,
) -> bool {
    stream.is_done()
        && !tracked_records.values().any(|record| {
            record
                .frames
                .iter()
                .any(|frame| frame.references_stream(stream_id))
        })
}

fn acknowledge_tracked_frame(
    streams: &mut IndexMap<StreamId, StreamState>,
    stream_send_buffer_size: usize,
    frame: &TrackedFrame,
    sink: &mut impl EventSink,
) {
    match frame {
        TrackedFrame::StreamReset(_) | TrackedFrame::StreamWindow(..) | TrackedFrame::Ping => {}
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
        .0
        .checked_add(1)
        .map(RecordSeq)
        .expect("record sequence overflow");
}
