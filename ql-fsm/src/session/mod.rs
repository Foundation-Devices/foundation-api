pub use self::{stream_ops::*, stream_parity::*};

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
    state::{InboundState, OutboundState, SessionState, StreamRole, StreamState},
    stream_tx::StreamTxRange,
    tracked::{LossRecovery, TrackedFrame, TrackedRecord, TrackedStreamData},
};
use crate::{StreamError, StreamMeta, StreamResetEvent, StreamResetTarget};

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

#[derive(Debug, PartialEq, Eq)]
pub enum SessionEvent {
    Opened(StreamId),
    SessionClosed {
        close: SessionClose,
        write: SessionRecordBuilder,
    },
    Unpaired {
        write: SessionRecordBuilder,
    },
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

pub struct SessionFsm<M> {
    config: SessionConfig,
    params: SessionParams,
    state: SessionState<M>,
}

impl<M: StreamMeta> SessionFsm<M> {
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
                next_stream_ordinal: 0,
                next_record_seq: RecordSeq(0),
                next_write_id: 0,
                tracked_records: IndexMap::default(),
                loss_recovery: LossRecovery::new(config.retransmit_timeout),
                replay_window: ReplayWindow::new(config.accepted_record_window),
                ack_tracker: AckTracker::new(config.pending_ack_range_limit),
                pending_ping: false,
                streams: IndexMap::default(),
                next_stream_index: 0,
                remote_stream_history: RemoteStreamHistory::new(params.local_parity.remote()),
            },
        }
    }

    pub fn open_stream(&mut self, header: Box<[u8]>) -> StreamOps<'_, M> {
        let stream_id = self
            .params
            .local_parity
            .make_stream_id(self.state.next_stream_ordinal);
        self.state.next_stream_ordinal = self.state.next_stream_ordinal.saturating_add(1);
        self.state.streams.insert(
            stream_id,
            StreamState::new(
                M::default(),
                StreamRole::Initiator,
                Some(Bytes::from(header)),
                self.config.stream_receive_buffer_size,
                self.params.initial_stream_receive_window,
            ),
        );
        let stream_index = self.state.streams.len() - 1;
        StreamOps::new(self, stream_id, stream_index)
    }

    pub fn stream(&mut self, stream_id: StreamId) -> Result<StreamOps<'_, M>, StreamError> {
        let Some(stream_index) = (|| {
            let index = self.state.streams.get_index_of(&stream_id)?;
            // Event::Opened only fires after we receive the first frame of a stream
            // prevent early access to streams
            let _ = self.state.streams[index].io.header.as_ref()?;
            Some(index)
        })() else {
            return Err(StreamError::MissingStream);
        };
        Ok(StreamOps::new(self, stream_id, stream_index))
    }

    pub fn queue_ping(&mut self) {
        self.state.pending_ping = true;
    }

    pub fn close(&mut self, code: SessionCloseCode, sink: &mut impl EventSink) {
        let close = SessionClose { code };
        let mut write = self.terminal_write();
        assert!(write.push_close(&close), "builder has capacity");
        sink.emit(SessionEvent::SessionClosed { close, write });
    }

    pub fn unpair(&mut self, sink: &mut impl EventSink) {
        let mut write = self.terminal_write();
        assert!(write.push_unpair(), "builder has capacity");
        sink.emit(SessionEvent::Unpaired { write });
    }

    pub fn is_replay(&self, seq: RecordSeq) -> bool {
        self.state.replay_window.is_replay(seq)
    }

    pub fn receive<I>(&mut self, now: Instant, seq: RecordSeq, frames: I, sink: &mut impl EventSink)
    where
        I: IntoIterator<Item = Result<SessionFrame<Bytes>, ql_wire::Error>>,
    {
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
                SessionFrame::Ack(ack) => self.process_record_ack(now, &ack),
                SessionFrame::StreamData(frame) => {
                    if self.handle_stream_data(frame, sink).is_err() {
                        self.close(SessionCloseCode::PROTOCOL, sink);
                        return;
                    }
                }
                SessionFrame::StreamWindow(frame) => self.handle_stream_window(&frame),
                SessionFrame::StreamReset(frame) => {
                    if self.handle_stream_reset(&frame).is_err() {
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
        self.collect_timeouts(now);
        if !self.config.peer_timeout.is_zero()
            && self.state.last_inbound_at + self.config.peer_timeout <= now
        {
            self.close(SessionCloseCode::TIMEOUT, sink);
            return;
        }
        if !self.config.keepalive_interval.is_zero()
            && self.state.last_activity_at + self.config.keepalive_interval <= now
        {
            self.state.pending_ping = true;
        }
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        let ack_deadline = self.state.ack_tracker.ack_deadline();
        let rto = self.state.loss_recovery.rto();
        let retransmit_deadline = self
            .state
            .tracked_records
            .values()
            .filter_map(|record| record.sent_at.map(|sent_at| sent_at + rto))
            .min();
        let keepalive_deadline = (!self.config.keepalive_interval.is_zero()
            && !self.state.pending_ping)
            .then_some(self.state.last_activity_at + self.config.keepalive_interval);
        let peer_timeout_deadline = (!self.config.peer_timeout.is_zero())
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

    pub fn take_next_write(&mut self, now: Instant) -> Option<(Option<u64>, SessionRecordBuilder)> {
        const TRACKED_RECORD_LIMIT: usize = 64;

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

        let should_track = outbound.ping_included || !outbound.frames.is_empty();
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
            ping_included: false,
            sent_at: None,
        };

        self.push_next_pending_stream_reset(&mut builder, &mut outbound);

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

    fn terminal_write(&mut self) -> SessionRecordBuilder {
        let seq = self.state.next_record_seq;
        next_seq(&mut self.state.next_record_seq);
        SessionRecordBuilder::new(seq, self.config.record_max_size)
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

        let start = self.state.next_stream_index % len;
        for offset in 0..len {
            let index = (start + offset) % len;
            let stream = self.state.streams.get_index_mut(index).unwrap().1;
            let Some(reset) = stream.io.pending_reset.as_ref() else {
                continue;
            };
            if !builder.push_stream_reset(reset) {
                break;
            }

            outbound.frames.push(TrackedFrame::StreamReset(
                stream.io.pending_reset.take().unwrap(),
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
            if !stream.io.pending_window {
                continue;
            }
            let frame = StreamWindow {
                stream_id,
                maximum_offset: Varint(stream.io.recv_limit()),
            };
            if !builder.push_stream_window(&frame) {
                break;
            }

            stream.io.pending_window = false;
            stream.io.advertised_max_offset = *frame.maximum_offset;
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

        let start = self.state.next_stream_index % len;
        let mut next_index = start;

        for offset in 0..len {
            let Some(max_payload) = builder.remaining_capacity().checked_sub(OVERHEAD) else {
                break;
            };

            let index = (start + offset) % len;
            let (&stream_id, stream) = self.state.streams.get_index_mut(index).unwrap();
            if matches!(stream.io.outbound_state, OutboundState::Reset(_)) {
                continue;
            }
            // The header shares the frame with the payload, so it has to come out of the same
            // budget, and that budget is set before poll_transmit picks the range.
            let header = match stream.io.role {
                StreamRole::Initiator if stream.io.tx.can_send_header() => {
                    stream.io.header.as_deref()
                }
                _ => None,
            };
            let Some(max_payload) = max_payload.checked_sub(header.map_or(0, <[u8]>::len)) else {
                continue;
            };
            let Some(candidate) = stream
                .io
                .tx
                .poll_transmit(max_payload, stream.io.peer_max_offset)
            else {
                continue;
            };
            let frame = StreamData {
                stream_id,
                offset: Varint(candidate.offset),
                header: if candidate.offset == 0 { header } else { None },
                fin: candidate.fin,
                bytes: stream.io.tx.ranged_bytes(candidate),
            };
            let res = builder.push_stream_data(&frame);
            assert!(res, "builder has capacity");

            if candidate.fin {
                stream.io.outbound_state = OutboundState::Finished;
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

    fn process_record_ack(&mut self, now: Instant, ack: &RecordAck) {
        let stream_send_buffer_size = self.config.stream_send_buffer_size;
        let mut latest_sent_at = None;
        let state = &mut self.state;
        for (_, record) in state
            .tracked_records
            .extract_if(.., |_, record| ack.contains(record.seq.0))
        {
            latest_sent_at = latest_sent_at.max(record.sent_at);
            for frame in &record.frames {
                acknowledge_tracked_frame(&mut state.streams, stream_send_buffer_size, frame);
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
        let mut timed_out = false;
        let state = &mut self.state;
        for (_, record) in state.tracked_records.extract_if(.., |_, record| {
            record.sent_at.is_some_and(|sent_at| sent_at + rto <= now)
        }) {
            restore_tracked_record(
                now,
                &mut state.ack_tracker,
                &mut state.pending_ping,
                &mut state.streams,
                record,
            );
            timed_out = true;
        }
        if timed_out {
            state.loss_recovery.on_timeout();
        }
        self.reap_reapable_streams();
    }

    fn handle_stream_data(
        &mut self,
        frame: StreamData<Bytes>,
        sink: &mut impl EventSink,
    ) -> Result<(), ()> {
        let send_buffer_size = self.config.stream_send_buffer_size;
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
        let readable_before = stream.io.readable_bytes();

        let opened = match (
            stream.io.role,
            stream.io.header.as_ref(),
            header,
            frame_offset,
        ) {
            (StreamRole::Responder, None, Some(header), 0) => {
                stream.io.header = Some(header);
                true
            }
            (StreamRole::Initiator, _, Some(_), _)
            | (StreamRole::Responder, None, Some(_), _)
            | (StreamRole::Responder, None, None, 0) => return Err(()),
            _ => false,
        };

        match stream.io.inbound_state {
            InboundState::Open => {}
            InboundState::Reset(_) => return Ok(()),
            InboundState::Finished => {
                // finished stream should always have a final offset
                let Some(final_offset) = stream.io.rx.final_offset() else {
                    debug_assert!(false, "finished stream must retain final offset");
                    return Ok(());
                };

                // retransmitted data for an already-finished stream is fine as long as it stays
                // within the finalized byte range and any repeated FIN lands on that same offset.
                if (!frame.fin || frame_end == final_offset) && frame_end <= final_offset {
                    return Ok(());
                }

                return Err(());
            }
        }

        let outcome = stream
            .io
            .rx
            .insert(frame_offset, fin, bytes)
            .map_err(|_| ())?;

        if outcome.became_complete {
            stream.io.inbound_state = InboundState::Finished;
        }
        let finished = outcome.became_complete && stream.io.header.is_some();

        if opened {
            sink.emit(SessionEvent::Opened(stream_id));
        }

        let became_readable =
            stream.io.header.is_some() && readable_before == 0 && stream.io.readable_bytes() > 0;
        if became_readable {
            let StreamState { metadata, io } = stream;
            metadata.on_readable(StreamIo::new(stream_id, io, send_buffer_size));
        }
        if finished {
            let StreamState { metadata, io } = stream;
            metadata.on_inbound_finished(StreamIo::new(stream_id, io, send_buffer_size));
        }

        self.try_reap_stream(stream_id);
        Ok(())
    }

    fn handle_stream_window(&mut self, frame: &StreamWindow) {
        let Some(stream) = self.state.streams.get_mut(&frame.stream_id) else {
            return;
        };

        let maximum_offset = *frame.maximum_offset;
        if maximum_offset > stream.io.peer_max_offset {
            stream.io.peer_max_offset = maximum_offset;
        }
    }

    fn handle_stream_reset(&mut self, frame: &StreamReset) -> Result<(), ()> {
        let stream_id = frame.stream_id;
        let stream = match self.state.streams.get_mut(&stream_id) {
            Some(stream) => stream,
            None => match self.create_remote_stream(stream_id)? {
                Some(stream) => stream,
                None => return Ok(()),
            },
        };

        let inbound = Self::target_affects_inbound(stream.io.role, frame.target)
            && !matches!(stream.io.inbound_state, InboundState::Reset(_));
        let outbound = Self::target_affects_outbound(stream.io.role, frame.target)
            && !matches!(stream.io.outbound_state, OutboundState::Reset(_));

        if inbound {
            stream.io.inbound_state = InboundState::Reset(frame.clone());
            stream.io.reset_recv();
        }
        if outbound {
            stream.io.outbound_state = OutboundState::Reset(frame.clone());
            stream.io.tx.clear();
            stream.io.pending_reset = None;
        }
        if inbound || outbound {
            let target = match (inbound, outbound) {
                (true, true) => StreamResetTarget::Both,
                (true, false) => StreamResetTarget::Reader,
                (false, true) => StreamResetTarget::Writer,
                (false, false) => unreachable!(),
            };
            stream.metadata.on_reset(StreamResetEvent {
                stream_id,
                code: frame.code,
                target,
                origin: crate::ResetOrigin::Peer,
            });
        }
        self.try_reap_stream(frame.stream_id);
        Ok(())
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
            next_stream_index,
            ..
        } = &mut self.state;
        let old_start = *next_stream_index;
        let mut old_index = 0usize;
        let mut retained = 0usize;
        let mut new_start = None;

        streams.retain(|&stream_id, stream| {
            let keep = !stream_is_reapable(tracked_records, stream_id, stream);
            if keep {
                if old_index >= old_start && new_start.is_none() {
                    new_start = Some(retained);
                }
                retained += 1;
            }
            old_index += 1;
            keep
        });

        *next_stream_index = new_start.unwrap_or(0);
    }

    fn try_reap_stream(&mut self, stream_id: StreamId) {
        let Some(index) = self.state.streams.get_index_of(&stream_id) else {
            return;
        };
        let stream = &self.state.streams[index];
        if !stream_is_reapable(&self.state.tracked_records, stream_id, stream) {
            return;
        }
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

    fn create_remote_stream(
        &mut self,
        stream_id: StreamId,
    ) -> Result<Option<&mut StreamState<M>>, ()> {
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
                M::default(),
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

fn restore_tracked_record<M>(
    now: Instant,
    ack_tracker: &mut AckTracker,
    pending_ping: &mut bool,
    streams: &mut IndexMap<StreamId, StreamState<M>>,
    record: TrackedRecord,
) {
    if let Some(ack) = record.ack {
        ack_tracker.restore_acked_ranges(&ack, now);
    }
    if record.ping_included {
        *pending_ping = true;
    }
    for frame in record.frames {
        match frame {
            TrackedFrame::StreamReset(reset) => {
                if let Some(stream) = streams.get_mut(&reset.stream_id) {
                    stream.io.pending_reset = Some(reset);
                }
            }
            TrackedFrame::StreamData(frame) => {
                let Some(stream) = streams.get_mut(&frame.stream_id) else {
                    continue;
                };
                if matches!(stream.io.outbound_state, OutboundState::Reset(_)) {
                    continue;
                }
                stream.io.tx.retransmit(StreamTxRange {
                    offset: frame.offset,
                    len: frame.len,
                    fin: frame.fin,
                });
                if frame.fin && matches!(stream.io.outbound_state, OutboundState::Finished) {
                    stream.io.outbound_state = OutboundState::FinQueued;
                }
            }
            TrackedFrame::StreamWindow(stream_id, maximum_offset) => {
                if let Some(stream) = streams.get_mut(&stream_id) {
                    stream.io.pending_window |= stream.io.recv_limit() >= maximum_offset;
                }
            }
        }
    }
}

fn stream_is_reapable<M>(
    tracked_records: &IndexMap<u64, TrackedRecord>,
    stream_id: StreamId,
    stream: &StreamState<M>,
) -> bool {
    let tracked_refs_stream = tracked_records.values().any(|record| {
        record
            .frames
            .iter()
            .any(|frame| frame.references_stream(stream_id))
    });
    if tracked_refs_stream {
        return false;
    }

    if !stream.io.tx.is_empty()
        || stream.io.pending_reset.is_some()
        || stream.io.pending_window
        || stream.io.readable_bytes() > 0
        || stream.io.rx.buffered_end_offset() > stream.io.rx.start_offset()
    {
        return false;
    }

    matches!(
        (&stream.io.inbound_state, &stream.io.outbound_state),
        (
            InboundState::Finished | InboundState::Reset(_),
            OutboundState::Finished | OutboundState::Reset(_),
        )
    )
}

fn acknowledge_tracked_frame<M: StreamMeta>(
    streams: &mut IndexMap<StreamId, StreamState<M>>,
    stream_send_buffer_size: usize,
    frame: &TrackedFrame,
) {
    match frame {
        TrackedFrame::StreamReset(_) | TrackedFrame::StreamWindow(..) => {}
        TrackedFrame::StreamData(frame) => {
            let stream_id = frame.stream_id;
            if let Some(stream) = streams.get_mut(&stream_id) {
                let was_full = stream.io.send_capacity(stream_send_buffer_size) == 0;
                let had_unacked_fin = frame.fin && stream.io.tx.has_unacked_fin();
                stream.io.tx.ack(StreamTxRange {
                    offset: frame.offset,
                    len: frame.len,
                    fin: frame.fin,
                });
                if was_full
                    && stream.io.send_capacity(stream_send_buffer_size) > 0
                    && stream.io.is_writable()
                {
                    let StreamState { metadata, io } = stream;
                    metadata.on_writable(StreamIo::new(stream_id, io, stream_send_buffer_size));
                }
                if had_unacked_fin && !stream.io.tx.has_unacked_fin() {
                    stream.metadata.on_outbound_finished(stream_id);
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
