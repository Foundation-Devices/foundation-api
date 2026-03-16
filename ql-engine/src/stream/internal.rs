use std::{collections::VecDeque, time::Instant};

use super::{state::*, *};
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
enum OutboundSelection {
    Ack,
    InitialFrame { tx_seq: StreamSeq },
    RetryFrame { tx_seq: StreamSeq },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamDisposition {
    Keep,
    Reap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimerAction {
    None,
    Fail,
}

impl StreamFsm {
    pub fn open_stream_inner(
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

    pub fn write_stream_inner(
        &mut self,
        stream_id: StreamId,
        bytes: Vec<u8>,
    ) -> Result<(), StreamError> {
        if bytes.is_empty() {
            return Ok(());
        }

        let Some(stream) = self.streams.get_mut(&stream_id) else {
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
        Self::drive_stream(stream, stream_id);
        Ok(())
    }

    pub fn finish_stream_inner(&mut self, stream_id: StreamId) -> Result<(), StreamError> {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
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
        Self::drive_stream(stream, stream_id);
        Ok(())
    }

    pub fn close_stream_inner(
        &mut self,
        stream_id: StreamId,
        target: CloseTarget,
        code: CloseCode,
        payload: Vec<u8>,
    ) -> Result<(), StreamError> {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
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
            Self::drive_stream(stream, stream_id);
        }

        Ok(())
    }

    pub fn receive_inner(
        &mut self,
        now: Instant,
        body: StreamBody,
        events: &mut impl StreamEventSink,
    ) {
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
                    let Some(stream) = self.streams.get_mut(&stream_id) else {
                        return;
                    };

                    match stream.control.buffer_incoming(tx_seq, frame) {
                        BufferIncomingResult::OutOfWindow => {
                            Self::queue_protocol_close(stream_id, stream, events);
                            StreamDisposition::Keep
                        }
                        BufferIncomingResult::Duplicate | BufferIncomingResult::AlreadyBuffered => {
                            stream.control.note_ack(now, self.config.ack_delay, true);
                            StreamDisposition::Keep
                        }
                        BufferIncomingResult::Buffered { out_of_order } => {
                            stream
                                .control
                                .note_ack(now, self.config.ack_delay, out_of_order);
                            Self::drain_committed_frames(stream_id, stream, events)
                        }
                    }
                };

                match disposition {
                    StreamDisposition::Keep => {}
                    StreamDisposition::Reap => {
                        self.streams.remove(&stream_id);
                        events.reaped(stream_id);
                    }
                }
            }
        }
    }

    pub fn next_outbound_inner(&mut self, now: Instant, valid_until: u64) -> Option<Outbound> {
        for offset in 0..self.streams.len() {
            let stream_id = self.streams.id_at_offset(offset)?;
            let selection = {
                let stream = self.streams.get(&stream_id)?;
                self.select_outbound(stream, now)
            };
            let Some(selection) = selection else {
                continue;
            };

            let outbound = match selection {
                OutboundSelection::Ack => {
                    let stream = self.streams.get_mut(&stream_id)?;
                    let ack = stream.control.current_ack();
                    stream.control.clear_ack_schedule();
                    stream.control.note_ack_sent(ack);
                    Outbound {
                        body: StreamBody::Ack(StreamAckBody {
                            stream_id,
                            ack,
                            valid_until,
                        }),
                        completion: OutboundCompletion::Ack { stream_id },
                    }
                }
                OutboundSelection::InitialFrame { tx_seq }
                | OutboundSelection::RetryFrame { tx_seq } => {
                    let issue_id = self.next_issue_id();
                    let stream = self.streams.get_mut(&stream_id)?;
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

            self.streams.advance_cursor_after(stream_id);
            return Some(outbound);
        }

        None
    }

    pub fn complete_outbound_inner(
        &mut self,
        now: Instant,
        completion: OutboundCompletion,
        result: Result<(), WriteError>,
        events: &mut impl StreamEventSink,
    ) {
        match completion {
            OutboundCompletion::Ack { stream_id } => {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    if result.is_err() {
                        stream.control.note_ack(now, self.config.ack_delay, true);
                    }
                    if stream.can_reap() {
                        self.streams.remove(&stream_id);
                        events.reaped(stream_id);
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
                        self.fail_stream_by_id(stream_id, StreamError::SendFailed, events);
                    }
                }
            },
        }
    }

    pub fn on_timer_inner(&mut self, now: Instant, events: &mut impl StreamEventSink) {
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
                } else {
                    TimerAction::None
                }
            };

            match action {
                TimerAction::Fail => {
                    self.fail_stream_by_id(stream_id, StreamError::Timeout, events);
                }
                TimerAction::None => {
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        if stream
                            .control
                            .ack_deadline()
                            .is_some_and(|due_at| due_at <= now)
                        {
                            stream.control.ack_state = AckState::Immediate;
                        }
                    }
                    index += 1;
                }
            }
        }
    }

    pub fn next_deadline_inner(&self) -> Option<Instant> {
        let mut next = None;
        for stream in self.streams.values() {
            if let Some(deadline) = stream.control.ack_deadline() {
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

    pub fn abort_inner(&mut self, error: StreamError, events: &mut impl StreamEventSink) {
        while let Some(stream_id) = self.streams.first_id() {
            self.fail_stream_by_id(stream_id, error.clone(), events);
        }
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

        matches!(stream.control.ack_state, AckState::Immediate).then_some(OutboundSelection::Ack)
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

    fn drain_committed_frames(
        stream_id: StreamId,
        stream: &mut StreamState,
        events: &mut impl StreamEventSink,
    ) -> StreamDisposition {
        loop {
            let Some((tx_seq, frame)) = stream.control.pop_next_committable() else {
                break;
            };

            if stream.awaiting_open()
                && (tx_seq != StreamSeq::START || !matches!(frame, StreamFrame::Open(_)))
            {
                Self::queue_protocol_close(stream_id, stream, events);
                return StreamDisposition::Keep;
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
        let opened = !stream.awaiting_open();
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
                    if opened {
                        events.outbound_failed(stream_id, StreamError::StreamProtocol);
                    }
                }
            }
            if let Some(inbound) = stream.inbound_mut(side) {
                if inbound.close() {
                    if opened {
                        events.inbound_failed(stream_id, StreamError::StreamProtocol);
                    }
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
