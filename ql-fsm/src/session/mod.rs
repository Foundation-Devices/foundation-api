pub(crate) mod reassembly;
pub(crate) mod state;

#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};

use indexmap::map::Entry;
use ql_wire::{
    CloseCode, CloseTarget, RecordAck, RecordSeq, SessionCloseBody, SessionFrame, SessionRecord,
    StreamClose, StreamData, StreamId, StreamWindow,
};

use self::{
    reassembly::{ByteReassemblyError, BytesIter},
    state::{
        AckState, InboundState, OutboundState, PendingRecord, ReceiveInsertOutcome,
        ReceivedRecords, ReliableFrame, SentRecord, SessionFsmState, StreamParity, StreamRole,
        StreamState,
    },
};

pub(crate) const SESSION_RECORD_TRACKED_WINDOW: u64 = 256;

#[derive(Debug, Clone, Copy)]
pub struct SessionFsmConfig {
    pub local_parity: StreamParity,
    pub record_size: usize,
    pub ack_delay: Duration,
    pub retransmit_timeout: Duration,
    pub keepalive_interval: Duration,
    pub peer_timeout: Duration,
    pub stream_send_buffer_size: usize,
    pub stream_receive_buffer_size: usize,
}

impl Default for SessionFsmConfig {
    fn default() -> Self {
        Self {
            local_parity: StreamParity::Even,
            record_size: 16 * 1024,
            ack_delay: Duration::from_millis(5),
            retransmit_timeout: Duration::from_millis(150),
            keepalive_interval: Duration::from_secs(10),
            peer_timeout: Duration::from_secs(30),
            stream_send_buffer_size: 64 * 1024,
            stream_receive_buffer_size: 64 * 1024,
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
    #[error("invalid read commit")]
    InvalidRead,
    #[error("session is closed")]
    SessionClosed,
}

pub struct SessionFsm {
    config: SessionFsmConfig,
    state: SessionFsmState,
}

impl SessionFsm {
    pub fn new(mut config: SessionFsmConfig, now: Instant) -> Self {
        config.record_size = config.record_size.max(64);
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
                issued_records: Default::default(),
                sent_records: Default::default(),
                received_records: ReceivedRecords::default(),
                ack_state: AckState::Idle,
                pending_control: Default::default(),
                streams: Default::default(),
                next_stream_index: 0,
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
                self.config.stream_send_buffer_size,
                self.config.stream_receive_buffer_size,
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
        stream.send_buf.extend(bytes[..accepted].iter().copied());
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
            Self::apply_local_close_to_stream(stream, target);
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

    pub fn stream_read(&self, stream_id: StreamId) -> Result<BytesIter<'_>, StreamError> {
        let stream = self
            .state
            .streams
            .get(&stream_id)
            .ok_or(StreamError::MissingStream)?;
        Ok(stream.recv.bytes())
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
        stream
            .recv
            .consume(len)
            .map_err(|_| StreamError::InvalidRead)?;
        if stream.recv_limit() > stream.advertised_max_offset {
            stream.pending_window = true;
        }
        self.try_reap_stream(stream_id);
        Ok(())
    }

    pub fn stream_available_bytes(&self, stream_id: StreamId) -> Result<usize, StreamError> {
        let stream = self
            .state
            .streams
            .get(&stream_id)
            .ok_or(StreamError::MissingStream)?;
        Ok(stream.readable_bytes())
    }

    pub fn queue_ping(&mut self) -> Result<(), StreamError> {
        self.ensure_session_open()?;
        self.state.pending_control.ping = true;
        Ok(())
    }

    pub fn receive(
        &mut self,
        now: Instant,
        record: SessionRecord,
        mut emit: impl FnMut(SessionEvent),
    ) {
        self.state.now = now;
        self.collect_timeouts();

        let ack_eliciting = Self::record_is_ack_eliciting(&record);
        self.state.last_activity_at = self.state.now;
        self.state.last_inbound_at = self.state.now;

        let out_of_order = match self.state.received_records.insert(record.seq) {
            ReceiveInsertOutcome::Duplicate => {
                if ack_eliciting {
                    self.schedule_ack(true);
                }
                return;
            }
            ReceiveInsertOutcome::New { out_of_order } => out_of_order,
        };

        if self.state.session_state == SessionState::Closed {
            if ack_eliciting {
                self.schedule_ack(true);
            }
            return;
        }

        for frame in record.frames {
            match frame {
                SessionFrame::Ping => {}
                SessionFrame::Ack(ack) => self.process_record_ack(ack, &mut emit),
                SessionFrame::StreamData(frame) => {
                    if self.handle_stream_data(frame, &mut emit).is_err() {
                        return;
                    }
                }
                SessionFrame::StreamWindow(frame) => {
                    if self.handle_stream_window(frame, &mut emit).is_err() {
                        return;
                    }
                }
                SessionFrame::StreamClose(frame) => {
                    if self.handle_stream_close(frame, &mut emit).is_err() {
                        return;
                    }
                }
                SessionFrame::Close(close) => {
                    self.handle_session_close(close, &mut emit);
                    return;
                }
            }
        }

        if ack_eliciting {
            self.schedule_ack(out_of_order);
        }
    }

    pub fn confirm_write(&mut self, now: Instant, write_id: u64) {
        self.state.now = now;
        let Some(pending) = self.state.issued_records.shift_remove(&write_id) else {
            return;
        };
        self.state.last_activity_at = now;
        self.state.sent_records.insert(
            pending.seq.0,
            SentRecord {
                pending,
                sent_at: now,
            },
        );
    }

    pub fn reject_write(&mut self, write_id: u64) {
        let Some(pending) = self.state.issued_records.shift_remove(&write_id) else {
            return;
        };
        self.restore_pending_record(pending);
    }

    pub fn on_timer(&mut self, now: Instant, mut emit: impl FnMut(SessionEvent)) {
        self.state.now = now;
        self.collect_timeouts();
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
            AckState::Immediate => Some(self.state.now),
            AckState::Delayed { due_at } => Some(due_at),
        };
        let retransmit_deadline = self
            .state
            .sent_records
            .values()
            .map(|record| record.sent_at + self.config.retransmit_timeout)
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
                || !stream.retransmit.is_empty()
                || !stream.send_buf.is_empty()
                || stream.pending_window
                || matches!(stream.outbound_state, OutboundState::FinQueued)
        })
    }

    pub fn take_next_write(&mut self, now: Instant) -> Option<(u64, SessionRecord)> {
        self.state.now = now;
        self.collect_timeouts();

        let built = self.build_next_record()?;
        let write_id = self.state.next_write_id;
        self.state.next_write_id = self.state.next_write_id.wrapping_add(1);
        self.state.issued_records.insert(write_id, built.pending);
        Some((write_id, built.record))
    }

    fn build_next_record(&mut self) -> Option<BuiltRecord> {
        let seq = self.state.next_record_seq;
        let mut record = SessionRecord {
            seq,
            frames: Vec::new(),
        };
        let mut pending = PendingRecord {
            seq,
            reliable: Vec::new(),
            ack_included: false,
            ping_included: false,
            window_updates: Vec::new(),
        };
        let mut remaining = self.config.record_size.saturating_sub(8);

        if self.should_send_ack() {
            if let Some(ack) = self.state.received_records.ack() {
                let frame = SessionFrame::Ack(ack);
                if self.push_frame(&mut record, &mut remaining, frame, true) {
                    pending.ack_included = true;
                    self.state.ack_state = AckState::Idle;
                }
            }
        }

        while let Some(close) = self.take_pending_session_close(remaining, record.frames.is_empty())
        {
            let frame = SessionFrame::Close(close.clone());
            if !self.push_frame(&mut record, &mut remaining, frame, true) {
                self.state.pending_control.close = Some(close);
                break;
            }
            pending.reliable.push(ReliableFrame::Close(close));
        }

        while let Some(close) =
            self.take_next_pending_stream_close(remaining, record.frames.is_empty())
        {
            let frame = SessionFrame::StreamClose(close.clone());
            if !self.push_frame(&mut record, &mut remaining, frame, true) {
                self.restore_stream_close(close);
                break;
            }
            pending.reliable.push(ReliableFrame::StreamClose(close));
        }

        if let Some(ping) = self.take_pending_ping(remaining, record.frames.is_empty()) {
            if self.push_frame(&mut record, &mut remaining, ping, true) {
                pending.ping_included = true;
            } else {
                self.state.pending_control.ping = true;
            }
        }

        while let Some(window) =
            self.take_next_pending_stream_window(remaining, record.frames.is_empty())
        {
            let maximum_offset = window.maximum_offset;
            let stream_id = window.stream_id;
            if !self.push_frame(
                &mut record,
                &mut remaining,
                SessionFrame::StreamWindow(window),
                true,
            ) {
                if let Some(stream) = self.state.streams.get_mut(&stream_id) {
                    stream.pending_window = true;
                }
                break;
            }
            pending.window_updates.push((stream_id, maximum_offset));
        }

        while let Some(frame) =
            self.take_next_retransmit_stream_data(remaining, record.frames.is_empty())
        {
            if !self.push_frame(
                &mut record,
                &mut remaining,
                SessionFrame::StreamData(frame.clone()),
                true,
            ) {
                self.restore_stream_data(frame);
                break;
            }
            pending.reliable.push(ReliableFrame::StreamData(frame));
        }

        while let Some(frame) =
            self.take_next_fresh_stream_data(remaining, record.frames.is_empty())
        {
            if !self.push_frame(
                &mut record,
                &mut remaining,
                SessionFrame::StreamData(frame.clone()),
                true,
            ) {
                self.restore_stream_data(frame);
                break;
            }
            pending.reliable.push(ReliableFrame::StreamData(frame));
        }

        if record.frames.is_empty() {
            return None;
        }

        self.state.next_record_seq = RecordSeq(self.state.next_record_seq.0.saturating_add(1));
        Some(BuiltRecord { record, pending })
    }

    fn take_pending_session_close(
        &mut self,
        remaining: usize,
        record_empty: bool,
    ) -> Option<SessionCloseBody> {
        let close = self.state.pending_control.close.clone()?;
        let frame = SessionFrame::Close(close.clone());
        if !self.frame_fits(remaining, record_empty, &frame) {
            return None;
        }
        self.state.pending_control.close.take()
    }

    fn take_pending_ping(&mut self, remaining: usize, record_empty: bool) -> Option<SessionFrame> {
        if !self.state.pending_control.ping {
            return None;
        }
        let frame = SessionFrame::Ping;
        if !self.frame_fits(remaining, record_empty, &frame) {
            return None;
        }
        self.state.pending_control.ping = false;
        Some(frame)
    }

    fn take_next_pending_stream_close(
        &mut self,
        remaining: usize,
        record_empty: bool,
    ) -> Option<StreamClose> {
        let len = self.state.streams.len();
        if len == 0 {
            return None;
        }

        let start = self.state.next_stream_index % len;
        for offset in 0..len {
            let index = (start + offset) % len;
            let Some((_, stream)) = self.state.streams.get_index(index) else {
                continue;
            };
            let Some(close) = stream.pending_close.clone() else {
                continue;
            };
            let frame = SessionFrame::StreamClose(close.clone());
            if !self.frame_fits(remaining, record_empty, &frame) {
                continue;
            }

            let stream = self.state.streams.get_index_mut(index).unwrap().1;
            self.state.next_stream_index = (index + 1) % len;
            return stream.pending_close.take().or(Some(close));
        }

        None
    }

    fn take_next_pending_stream_window(
        &mut self,
        remaining: usize,
        record_empty: bool,
    ) -> Option<StreamWindow> {
        let len = self.state.streams.len();
        if len == 0 {
            return None;
        }

        let start = self.state.next_stream_index % len;
        for offset in 0..len {
            let index = (start + offset) % len;
            let Some((&stream_id, stream)) = self.state.streams.get_index(index) else {
                continue;
            };
            if !stream.pending_window {
                continue;
            }
            let frame = StreamWindow {
                stream_id,
                maximum_offset: stream.recv_limit(),
            };
            if !self.frame_fits(
                remaining,
                record_empty,
                &SessionFrame::StreamWindow(frame.clone()),
            ) {
                continue;
            }

            let (_, stream) = self.state.streams.get_index_mut(index).unwrap();
            stream.pending_window = false;
            stream.advertised_max_offset = frame.maximum_offset;
            self.state.next_stream_index = (index + 1) % len;
            return Some(frame);
        }

        None
    }

    fn take_next_retransmit_stream_data(
        &mut self,
        remaining: usize,
        record_empty: bool,
    ) -> Option<StreamData> {
        let max_payload = self.max_stream_data_payload(remaining, record_empty)?;
        let len = self.state.streams.len();
        if len == 0 {
            return None;
        }

        let start = self.state.next_stream_index % len;
        for offset in 0..len {
            let index = (start + offset) % len;
            let Some((_, stream)) = self.state.streams.get_index(index) else {
                continue;
            };

            if matches!(stream.outbound_state, OutboundState::Closed) {
                let (_, stream) = self.state.streams.get_index_mut(index).unwrap();
                while let Some(frame) = stream.retransmit.pop_front() {
                    stream.inflight_bytes = stream.inflight_bytes.saturating_sub(frame.bytes.len());
                }
                continue;
            }

            let Some(_) = stream.retransmit.front() else {
                continue;
            };
            let (_, stream) = self.state.streams.get_index_mut(index).unwrap();
            let frame = stream.retransmit.pop_front().unwrap();
            let (head, tail) = Self::split_stream_data(frame, max_payload);
            if let Some(tail) = tail {
                stream.retransmit.push_front(tail);
            }
            self.state.next_stream_index = (index + 1) % len;
            return Some(head);
        }

        None
    }

    fn take_next_fresh_stream_data(
        &mut self,
        remaining: usize,
        record_empty: bool,
    ) -> Option<StreamData> {
        let max_payload = self.max_stream_data_payload(remaining, record_empty)?;
        let len = self.state.streams.len();
        if len == 0 {
            return None;
        }

        let start = self.state.next_stream_index % len;
        for offset in 0..len {
            let index = (start + offset) % len;
            let Some((&stream_id, stream)) = self.state.streams.get_index(index) else {
                continue;
            };
            if matches!(stream.outbound_state, OutboundState::Closed) {
                continue;
            }

            let credit_remaining = stream
                .peer_max_offset
                .saturating_sub(stream.next_send_offset)
                as usize;
            let has_empty_fin = matches!(stream.outbound_state, OutboundState::FinQueued)
                && stream.send_buf.is_empty()
                && stream.next_send_offset <= stream.peer_max_offset;
            if stream.send_buf.is_empty() && !has_empty_fin {
                continue;
            }

            if credit_remaining == 0 && !has_empty_fin {
                continue;
            }

            let (_, stream) = self.state.streams.get_index_mut(index).unwrap();
            let payload_len = stream.send_buf.len().min(max_payload).min(credit_remaining);
            let bytes: Vec<u8> = stream.send_buf.drain(..payload_len).collect();
            let fin = matches!(stream.outbound_state, OutboundState::FinQueued)
                && stream.send_buf.is_empty()
                && stream.next_send_offset + bytes.len() as u64 <= stream.peer_max_offset;
            let frame = StreamData {
                stream_id,
                offset: stream.next_send_offset,
                fin,
                bytes,
            };
            stream.next_send_offset = stream
                .next_send_offset
                .saturating_add(frame.bytes.len() as u64);
            stream.inflight_bytes = stream.inflight_bytes.saturating_add(frame.bytes.len());
            if fin {
                stream.outbound_state = OutboundState::Finished;
            }
            self.state.next_stream_index = (index + 1) % len;
            return Some(frame);
        }

        None
    }

    fn ensure_session_open(&self) -> Result<(), StreamError> {
        if self.state.session_state == SessionState::Closed {
            Err(StreamError::SessionClosed)
        } else {
            Ok(())
        }
    }

    fn process_record_ack(&mut self, ack: RecordAck, emit: &mut impl FnMut(SessionEvent)) {
        let acked: Vec<u64> = self
            .state
            .sent_records
            .keys()
            .copied()
            .filter(|seq| Self::ack_covers(&ack, RecordSeq(*seq)))
            .collect();

        for seq in acked {
            let Some(sent) = self.state.sent_records.shift_remove(&seq) else {
                continue;
            };
            for frame in sent.pending.reliable {
                self.acknowledge_reliable_frame(frame, emit);
            }
        }
    }

    fn ack_covers(ack: &RecordAck, seq: RecordSeq) -> bool {
        ack.ranges
            .iter()
            .any(|range| range.start <= seq.0 && seq.0 < range.end)
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

    fn should_send_ack(&self) -> bool {
        if self.state.received_records.ack().is_none() {
            return false;
        }
        match self.state.ack_state {
            AckState::Immediate => true,
            AckState::Delayed { due_at } => due_at <= self.state.now,
            AckState::Idle => false,
        }
    }

    fn collect_timeouts(&mut self) {
        let expired: Vec<u64> = self
            .state
            .sent_records
            .iter()
            .filter_map(|(seq, record)| {
                (record.sent_at + self.config.retransmit_timeout <= self.state.now).then_some(*seq)
            })
            .collect();

        for seq in expired {
            let Some(sent) = self.state.sent_records.shift_remove(&seq) else {
                continue;
            };
            self.restore_pending_record(sent.pending);
        }
    }

    fn restore_pending_record(&mut self, pending: PendingRecord) {
        if pending.ack_included {
            self.schedule_ack(true);
        }
        if pending.ping_included {
            self.state.pending_control.ping = true;
        }
        for (stream_id, maximum_offset) in pending.window_updates {
            if let Some(stream) = self.state.streams.get_mut(&stream_id) {
                if stream.recv_limit() >= maximum_offset {
                    stream.pending_window = true;
                }
            }
        }
        for frame in pending.reliable {
            self.requeue_reliable_frame(frame);
        }
    }

    fn requeue_reliable_frame(&mut self, frame: ReliableFrame) {
        match frame {
            ReliableFrame::Close(close) => {
                self.state.pending_control.close = Some(close);
            }
            ReliableFrame::StreamClose(close) => self.restore_stream_close(close),
            ReliableFrame::StreamData(frame) => self.restore_stream_data(frame),
        }
    }

    fn acknowledge_reliable_frame(
        &mut self,
        frame: ReliableFrame,
        emit: &mut impl FnMut(SessionEvent),
    ) {
        match frame {
            ReliableFrame::Close(_) => {}
            ReliableFrame::StreamClose(frame) => {
                self.try_reap_stream(frame.stream_id);
            }
            ReliableFrame::StreamData(frame) => {
                let stream_id = frame.stream_id;
                if let Some(stream) = self.state.streams.get_mut(&stream_id) {
                    let was_full = stream.send_capacity(self.config.stream_send_buffer_size) == 0;
                    stream.inflight_bytes = stream.inflight_bytes.saturating_sub(frame.bytes.len());
                    if was_full && stream.send_capacity(self.config.stream_send_buffer_size) > 0 {
                        emit(SessionEvent::Writable(stream_id));
                    }
                }
                self.try_reap_stream(stream_id);
            }
        }
    }

    fn handle_stream_data(
        &mut self,
        frame: StreamData,
        emit: &mut impl FnMut(SessionEvent),
    ) -> Result<(), ()> {
        let stream_id = frame.stream_id;
        let stream = match self.state.streams.entry(stream_id) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                if !self.config.local_parity.remote().matches(stream_id) {
                    self.fail_session(
                        SessionCloseBody {
                            code: CloseCode::PROTOCOL,
                        },
                        emit,
                    );
                    return Err(());
                }
                emit(SessionEvent::Opened(stream_id));
                entry.insert(StreamState::new(
                    StreamRole::Responder,
                    self.config.stream_send_buffer_size,
                    self.config.stream_receive_buffer_size,
                ))
            }
        };

        match stream.inbound_state {
            InboundState::Open => {}
            InboundState::Discarding => return Ok(()),
            InboundState::Finished | InboundState::Closed(_) => {
                if frame.offset + frame.bytes.len() as u64 <= stream.recv.start_offset() {
                    return Ok(());
                }
                self.fail_session(
                    SessionCloseBody {
                        code: CloseCode::PROTOCOL,
                    },
                    emit,
                );
                return Err(());
            }
        }

        let was_readable = stream.readable_bytes() > 0;
        let insert = stream.recv.insert(frame.offset, frame.fin, &frame.bytes);
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
            Err(ByteReassemblyError::ConflictingOverlap)
            | Err(ByteReassemblyError::OutOfWindow)
            | Err(ByteReassemblyError::InconsistentFinalOffset)
            | Err(ByteReassemblyError::FinalOffsetBeforeBufferedData)
            | Err(ByteReassemblyError::BeyondFinalOffset)
            | Err(ByteReassemblyError::TooManyMissingRanges)
            | Err(ByteReassemblyError::OffsetOverflow) => {
                self.fail_session(
                    SessionCloseBody {
                        code: CloseCode::PROTOCOL,
                    },
                    emit,
                );
                Err(())
            }
            Err(ByteReassemblyError::ConsumeBeyondReadable) => unreachable!(),
        }
    }

    fn handle_stream_window(
        &mut self,
        frame: StreamWindow,
        emit: &mut impl FnMut(SessionEvent),
    ) -> Result<(), ()> {
        let Some(stream) = self.state.streams.get_mut(&frame.stream_id) else {
            self.fail_session(
                SessionCloseBody {
                    code: CloseCode::PROTOCOL,
                },
                emit,
            );
            return Err(());
        };

        let was_full = stream.send_capacity(self.config.stream_send_buffer_size) == 0;
        if frame.maximum_offset > stream.peer_max_offset {
            stream.peer_max_offset = frame.maximum_offset;
        }
        if was_full && stream.send_capacity(self.config.stream_send_buffer_size) > 0 {
            emit(SessionEvent::Writable(frame.stream_id));
        }
        Ok(())
    }

    fn handle_stream_close(
        &mut self,
        frame: StreamClose,
        emit: &mut impl FnMut(SessionEvent),
    ) -> Result<(), ()> {
        let created = match self.state.streams.entry(frame.stream_id) {
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                if !self.config.local_parity.remote().matches(frame.stream_id) {
                    self.fail_session(
                        SessionCloseBody {
                            code: CloseCode::PROTOCOL,
                        },
                        emit,
                    );
                    return Err(());
                }
                entry.insert(StreamState::new(
                    StreamRole::Responder,
                    self.config.stream_send_buffer_size,
                    self.config.stream_receive_buffer_size,
                ));
                true
            }
        };

        let stream = self.state.streams.get_mut(&frame.stream_id).unwrap();
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
            stream.send_buf.clear();
            stream.retransmit.clear();
            stream.pending_close = None;
            stream.inflight_bytes = 0;
            emit(SessionEvent::WritableClosed(frame.stream_id));
        }
        self.try_reap_stream(frame.stream_id);
        Ok(())
    }

    fn handle_session_close(
        &mut self,
        close: SessionCloseBody,
        emit: &mut impl FnMut(SessionEvent),
    ) {
        if self.state.session_state == SessionState::Closed {
            return;
        }

        self.state.session_state = SessionState::Closed;
        self.state.issued_records.clear();
        self.state.sent_records.clear();
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
            stream.send_buf.clear();
            stream.retransmit.clear();
        }
    }

    fn target_affects_inbound(role: StreamRole, target: CloseTarget) -> bool {
        matches!(target, CloseTarget::Both) || role.inbound_target() == target
    }

    fn target_affects_outbound(role: StreamRole, target: CloseTarget) -> bool {
        matches!(target, CloseTarget::Both) || role.outbound_target() == target
    }

    fn restore_stream_close(&mut self, close: StreamClose) {
        if let Some(stream) = self.state.streams.get_mut(&close.stream_id) {
            stream.pending_close = Some(close);
        }
    }

    fn restore_stream_data(&mut self, frame: StreamData) {
        if let Some(stream) = self.state.streams.get_mut(&frame.stream_id) {
            if matches!(stream.outbound_state, OutboundState::Closed) {
                stream.inflight_bytes = stream.inflight_bytes.saturating_sub(frame.bytes.len());
                return;
            }
            stream.retransmit.push_front(frame);
        }
    }

    fn split_stream_data(
        frame: StreamData,
        max_payload: usize,
    ) -> (StreamData, Option<StreamData>) {
        if frame.bytes.len() <= max_payload || frame.bytes.is_empty() {
            return (frame, None);
        }

        let split = max_payload.max(1).min(frame.bytes.len());
        let mut head = frame.clone();
        head.bytes.truncate(split);
        head.fin = false;

        let tail = StreamData {
            stream_id: frame.stream_id,
            offset: frame.offset + split as u64,
            fin: frame.fin,
            bytes: frame.bytes[split..].to_vec(),
        };
        (head, Some(tail))
    }

    fn max_stream_data_payload(&self, remaining: usize, record_empty: bool) -> Option<usize> {
        let overhead = self.frame_len(&SessionFrame::StreamData(StreamData {
            stream_id: StreamId(0),
            offset: 0,
            fin: false,
            bytes: Vec::new(),
        }));
        if remaining > overhead {
            Some(remaining - overhead)
        } else if record_empty {
            Some(self.config.record_size)
        } else {
            None
        }
    }

    fn frame_fits(&self, remaining: usize, record_empty: bool, frame: &SessionFrame) -> bool {
        let len = self.frame_len(frame);
        len <= remaining || record_empty
    }

    fn push_frame(
        &self,
        record: &mut SessionRecord,
        remaining: &mut usize,
        frame: SessionFrame,
        force_if_empty: bool,
    ) -> bool {
        let len = self.frame_len(&frame);
        if len > *remaining && !(force_if_empty && record.frames.is_empty()) {
            return false;
        }
        record.frames.push(frame);
        *remaining = remaining.saturating_sub(len);
        true
    }

    fn frame_len(&self, frame: &SessionFrame) -> usize {
        let mut bytes = Vec::new();
        frame.encode_into(&mut bytes);
        bytes.len()
    }

    fn record_is_ack_eliciting(record: &SessionRecord) -> bool {
        record
            .frames
            .iter()
            .any(|frame| !matches!(frame, SessionFrame::Ack(_)))
    }

    fn stream_is_reapable(&self, stream_id: StreamId, stream: &StreamState) -> bool {
        let issued_refs_stream = self.state.issued_records.values().any(|record| {
            record.window_updates.iter().any(|(id, _)| *id == stream_id)
                || record.reliable.iter().any(|frame| match frame {
                    ReliableFrame::StreamData(frame) => frame.stream_id == stream_id,
                    ReliableFrame::StreamClose(frame) => frame.stream_id == stream_id,
                    ReliableFrame::Close(_) => false,
                })
        });
        if issued_refs_stream {
            return false;
        }

        let sent_refs_stream = self.state.sent_records.values().any(|record| {
            record
                .pending
                .window_updates
                .iter()
                .any(|(id, _)| *id == stream_id)
                || record.pending.reliable.iter().any(|frame| match frame {
                    ReliableFrame::StreamData(frame) => frame.stream_id == stream_id,
                    ReliableFrame::StreamClose(frame) => frame.stream_id == stream_id,
                    ReliableFrame::Close(_) => false,
                })
        });
        if sent_refs_stream {
            return false;
        }

        if !stream.send_buf.is_empty()
            || !stream.retransmit.is_empty()
            || stream.pending_close.is_some()
            || stream.inflight_bytes > 0
            || stream.readable_bytes() > 0
            || stream.recv.buffered_end_offset() > stream.recv.start_offset()
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
        self.state.issued_records.clear();
        self.state.sent_records.clear();
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

struct BuiltRecord {
    record: SessionRecord,
    pending: PendingRecord,
}
