use std::cmp::Reverse;

use super::*;
use crate::{
    engine::{
        state::{StreamNamespace, TimeoutEntry},
        stream::*,
        EngineConfig, EngineState, StreamConfig,
    },
    wire::stream::*,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamHandleResult {
    Keep,
    Remove,
    Reap,
}

pub fn open_stream(
    engine: &mut Engine,
    now: Instant,
    request_head: Vec<u8>,
    request_prefix: Option<BodyChunk>,
    _config: StreamConfig,
) -> Result<StreamId, QlError> {
    let Some(entry) = engine.peer.as_ref() else {
        return Err(QlError::NoPeerBound);
    };
    if !entry.session.is_connected() {
        return Err(QlError::MissingSession);
    }

    let stream_namespace = StreamNamespace::for_local(engine.identity.xid, entry.peer);
    let stream_id = engine.state.next_stream_id(stream_namespace);
    let request_prefix_fin = request_prefix.as_ref().is_some_and(|chunk| chunk.fin);
    let frame = StreamFrameOpen {
        stream_id,
        request_head,
        request_prefix,
    };
    let mut stream = StreamState {
        meta: StreamMeta {
            stream_id,
            last_activity: now,
        },
        control: StreamControl {
            pending: std::collections::VecDeque::from([StreamFrame::Open(frame)]),
            ..Default::default()
        },
        role: StreamRole::Initiator(InitiatorStream {
            request: OutboundState::from_prefix(Direction::Request, request_prefix_fin),
            response: InboundState::new(),
        }),
    };
    drive_stream(&mut stream);
    engine.streams.insert(stream_id, stream);
    Ok(stream_id)
}

pub fn handle_close_stream(
    engine: &mut Engine,
    now: Instant,
    stream_id: StreamId,
    target: CloseTarget,
    code: CloseCode,
    payload: Vec<u8>,
) {
    let Some(stream) = engine.streams.get_mut(&stream_id) else {
        return;
    };
    apply_local_close(stream, target);
    stream
        .control
        .queue_frame_front(close_frame(stream_id, target, code, payload));
    stream.meta.last_activity = now;
    drive_stream(stream);
}

pub fn handle_outbound_data(
    engine: &mut Engine,
    stream_id: StreamId,
    dir: Direction,
    bytes: Vec<u8>,
) {
    if bytes.is_empty() {
        return;
    }
    let Some(stream) = engine.streams.get_mut(&stream_id) else {
        return;
    };
    if let StreamRole::Responder(state) = &mut stream.role {
        if dir == Direction::Response {
            state.response_started = true;
        }
    }
    let Some(outbound) = stream.outbound_mut(dir) else {
        return;
    };
    if !outbound.can_queue_data() {
        return;
    }
    let chunk = BodyChunk { bytes, fin: false };
    stream
        .control
        .queue_frame_back(StreamFrame::Data(StreamFrameData {
            stream_id,
            dir,
            chunk,
        }));
    drive_stream(stream);
}

pub fn handle_outbound_finished(engine: &mut Engine, stream_id: StreamId, dir: Direction) {
    let Some(stream) = engine.streams.get_mut(&stream_id) else {
        return;
    };
    if let StreamRole::Responder(state) = &mut stream.role {
        if dir == Direction::Response {
            state.response_started = true;
        }
    }
    let Some(outbound) = stream.outbound_mut(dir) else {
        return;
    };
    outbound.finish();
    drive_stream(stream);
}

pub fn handle_close_outbound(
    engine: &mut Engine,
    now: Instant,
    stream_id: StreamId,
    dir: Direction,
    code: CloseCode,
    payload: Vec<u8>,
) {
    let Some(stream) = engine.streams.get_mut(&stream_id) else {
        return;
    };
    let Some(outbound) = stream.outbound_mut(dir) else {
        return;
    };
    if outbound.is_closed() {
        return;
    }
    outbound.close();
    stream.control.queue_frame_front(close_frame(
        stream_id,
        close_target_for_dir(dir),
        code,
        payload,
    ));
    stream.meta.last_activity = now;
    drive_stream(stream);
}

pub fn handle_close_inbound(
    engine: &mut Engine,
    now: Instant,
    stream_id: StreamId,
    dir: Direction,
    code: CloseCode,
    payload: Vec<u8>,
) {
    let Some(stream) = engine.streams.get_mut(&stream_id) else {
        return;
    };
    let Some(inbound) = stream.inbound_mut(dir) else {
        return;
    };
    if inbound.closed {
        return;
    }
    inbound.closed = true;
    let target = close_target_for_dir(dir);
    stream
        .control
        .queue_frame_front(close_frame(stream_id, target, code, payload));
    stream.meta.last_activity = now;
    drive_stream(stream);
}

pub fn handle_responder_dropped(engine: &mut Engine, now: Instant, stream_id: StreamId) {
    handle_close_stream(
        engine,
        now,
        stream_id,
        CloseTarget::Both,
        CloseCode::UNHANDLED,
        Vec::new(),
    );
}

pub fn handle_stream(
    engine: &mut Engine,
    now: Instant,
    _peer: XID,
    header: &QlHeader,
    encrypted: &mut ArchivedEncryptedMessage,
    emit: &mut impl OutputFn,
) {
    let body = {
        let Some(peer_record) = engine.peer.as_ref() else {
            return;
        };
        let PeerSession::Connected { session_key, .. } = &peer_record.session else {
            return;
        };
        match decrypt_stream(header, encrypted, session_key) {
            Ok(body) => body,
            Err(_) => return,
        }
    };
    engine.record_activity(now);

    let message = match body {
        StreamBody::Ack(StreamAckBody { stream_id, ack, .. }) => {
            process_stream_ack(engine, now, stream_id, ack, emit);
            if let Some(stream) = engine.streams.get_mut(&stream_id) {
                stream.meta.last_activity = now;
            }
            maybe_reap_stream(engine, stream_id, emit);
            return;
        }
        StreamBody::Message(message) => message,
    };

    let stream_id = message.frame.stream_id();
    process_stream_ack(engine, now, stream_id, message.ack, emit);

    if !engine.streams.contains_key(&stream_id) {
        let Some(peer_record) = engine.peer.as_ref() else {
            return;
        };
        let local_namespace = StreamNamespace::for_local(engine.identity.xid, peer_record.peer);
        if !local_namespace.remote().matches(stream_id) {
            return;
        }
        let token = engine.state.next_token();
        engine.streams.insert(
            stream_id,
            StreamState {
                meta: StreamMeta {
                    stream_id,
                    last_activity: now,
                },
                control: StreamControl::default(),
                role: StreamRole::Provisional(ProvisionalStream {
                    timeout_token: token,
                }),
            },
        );
        engine.state.timeouts.push(Reverse(TimeoutEntry {
            at: now + engine.config.packet_expiration,
            kind: TimeoutKind::StreamProvisional { stream_id, token },
        }));
    }

    let disposition = {
        let (state, streams) = (&mut engine.state, &mut engine.streams);
        let Some(stream) = streams.get_mut(&stream_id) else {
            return;
        };
        stream.meta.last_activity = now;

        match stream
            .control
            .buffer_incoming(message.tx_seq, message.frame)
        {
            BufferIncomingResult::OutOfWindow => {
                if stream.is_provisional() {
                    state.enqueue_stream_close(
                        &engine.config,
                        true,
                        stream_id,
                        CloseTarget::Both,
                        CloseCode::PROTOCOL,
                        Vec::new(),
                    );
                    StreamHandleResult::Remove
                } else {
                    queue_protocol_close(stream, emit);
                    stream.meta.last_activity = now;
                    StreamHandleResult::Keep
                }
            }
            BufferIncomingResult::Duplicate | BufferIncomingResult::AlreadyBuffered => {
                stream.control.note_ack(true);
                schedule_stream_ack(state, &engine.config, stream, now);
                StreamHandleResult::Keep
            }
            BufferIncomingResult::Buffered { out_of_order } => {
                stream.control.note_ack(out_of_order);
                drain_committed_stream_frames(state, &engine.config, stream, now, emit)
            }
        }
    };
    match disposition {
        StreamHandleResult::Keep => {}
        StreamHandleResult::Remove => {
            engine.streams.remove(&stream_id);
        }
        StreamHandleResult::Reap => {
            engine.streams.remove(&stream_id);
            emit(EngineOutput::StreamReaped { stream_id });
        }
    }
}

pub fn take_next_stream_write(
    engine: &mut Engine,
    crypto: &impl QlCrypto,
) -> Option<OutboundWrite> {
    let (recipient, session_key) = engine.stream_write_session()?;
    let stream_ids: Vec<_> = engine.streams.scan_from_cursor().collect();
    for stream_id in stream_ids {
        let write = take_next_write_for_stream(engine, stream_id, recipient, &session_key, crypto);
        if write.is_some() {
            engine.streams.advance_cursor_after(stream_id);
            return write;
        }
    }
    None
}

pub fn process_stream_ack(
    engine: &mut Engine,
    now: Instant,
    stream_id: StreamId,
    ack: StreamAck,
    emit: &mut impl OutputFn,
) {
    if ack == StreamAck::EMPTY {
        return;
    }

    let should_reap = {
        let Some(stream) = engine.streams.get_mut(&stream_id) else {
            return;
        };
        stream.control.clear_fast_recovery(ack.base);
        let fast_retransmit = stream
            .control
            .fast_retransmit_candidate(ack, engine.config.stream_fast_retransmit_threshold);

        loop {
            let acked_tx_seq = stream
                .control
                .in_flight
                .iter()
                .find_map(|(tx_seq, in_flight)| match in_flight.write_state {
                    // ignore acks for writes that have not been sent out yet
                    InFlightWriteState::Ready => None,
                    InFlightWriteState::Issued | InFlightWriteState::WaitingRetry { .. } => {
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
                    if let StreamRole::Initiator(stream) = &mut stream.role {
                        if request_prefix.as_ref().is_some_and(|chunk| chunk.fin) {
                            stream.request.close();
                            emit(EngineOutput::OutboundClosed {
                                stream_id,
                                dir: Direction::Request,
                            });
                        }
                    }
                }
                StreamFrame::Data(StreamFrameData {
                    dir,
                    chunk: BodyChunk { fin: true, .. },
                    ..
                }) => {
                    if let Some(outbound) = stream.outbound_mut(dir) {
                        outbound.close();
                        emit(EngineOutput::OutboundClosed { stream_id, dir });
                    }
                }
                StreamFrame::Close(StreamFrameClose {
                    target,
                    code,
                    payload,
                    ..
                }) => {
                    for outbound_dir in [Direction::Request, Direction::Response] {
                        let affects_outbound = matches!(
                            (target, outbound_dir),
                            (CloseTarget::Request, Direction::Request)
                                | (CloseTarget::Response, Direction::Response)
                                | (CloseTarget::Both, _)
                        );
                        if affects_outbound {
                            if let Some(outbound) = stream.outbound_mut(outbound_dir) {
                                outbound.close();
                                emit(EngineOutput::OutboundFailed {
                                    stream_id,
                                    dir: outbound_dir,
                                    error: QlError::StreamClosed {
                                        target,
                                        code,
                                        payload: payload.clone(),
                                    },
                                });
                            }
                        }
                    }
                }
                StreamFrame::Data(_) => {}
            }
        }

        if let Some(tx_seq) = fast_retransmit {
            stream.control.schedule_fast_retransmit(tx_seq, now);
        }
        drive_stream(stream);
        stream.can_reap()
    };

    if should_reap {
        engine.streams.remove(&stream_id);
        emit(EngineOutput::StreamReaped { stream_id });
    }
}

fn schedule_stream_ack(
    state: &mut EngineState,
    config: &EngineConfig,
    stream: &mut StreamState,
    now: Instant,
) {
    let stream_id = stream.meta.stream_id;
    let control = &mut stream.control;
    if !control.ack_dirty {
        return;
    }
    if control.ack_immediate || config.stream_ack_delay.is_zero() {
        control.ack_delay_token = None;
        return;
    }
    if control.ack_delay_token.is_some() {
        return;
    }
    let token = state.next_token();
    control.ack_delay_token = Some(token);
    state.timeouts.push(Reverse(TimeoutEntry {
        at: now + config.stream_ack_delay,
        kind: TimeoutKind::StreamAckDelay { stream_id, token },
    }));
}

fn drain_committed_stream_frames(
    state: &mut EngineState,
    config: &EngineConfig,
    stream: &mut StreamState,
    now: Instant,
    emit: &mut impl OutputFn,
) -> StreamHandleResult {
    let stream_id = stream.meta.stream_id;
    loop {
        let next = stream.control.pop_next_committable();
        let Some((_tx_seq, frame)) = next else {
            break;
        };
        if stream.is_provisional() && !matches!(frame, StreamFrame::Open(_)) {
            state.enqueue_stream_close(
                config,
                true,
                stream_id,
                CloseTarget::Both,
                CloseCode::PROTOCOL,
                Vec::new(),
            );
            return StreamHandleResult::Remove;
        }
        match frame {
            StreamFrame::Open(frame) => handle_stream_open(stream, now, frame, emit),
            StreamFrame::Close(frame) => handle_stream_close_from_peer(stream, frame, emit),
            StreamFrame::Data(frame) => handle_stream_data(stream, now, frame, emit),
        }
    }
    stream.control.maybe_force_ack_for_progress();
    schedule_stream_ack(state, config, stream, now);
    if stream.can_reap() {
        StreamHandleResult::Reap
    } else {
        StreamHandleResult::Keep
    }
}

fn handle_stream_open(
    stream: &mut StreamState,
    now: Instant,
    frame: StreamFrameOpen,
    emit: &mut impl OutputFn,
) {
    let StreamFrameOpen {
        stream_id,
        request_head,
        request_prefix,
    } = frame;
    if !stream.is_provisional() {
        queue_protocol_close(stream, emit);
        return;
    }
    stream.meta.last_activity = now;
    stream.role = StreamRole::Responder(ResponderStream {
        request: InboundState::new(),
        response: OutboundState::from_prefix(Direction::Response, false),
        response_started: false,
    });
    if let Some(chunk) = request_prefix.as_ref() {
        let Some(inbound) = stream.inbound_mut(Direction::Request) else {
            return;
        };
        if chunk.fin {
            inbound.closed = true;
        }
    }
    emit(EngineOutput::InboundStreamOpened {
        stream_id,
        request_head,
        request_prefix,
    });
}

fn handle_stream_close_from_peer(
    stream: &mut StreamState,
    frame: StreamFrameClose,
    emit: &mut impl OutputFn,
) {
    let StreamFrameClose {
        target,
        code,
        payload,
        ..
    } = frame;
    apply_remote_close(stream, target, code, payload, emit);
}

fn handle_stream_data(
    stream: &mut StreamState,
    now: Instant,
    frame: StreamFrameData,
    emit: &mut impl OutputFn,
) {
    let StreamFrameData {
        stream_id,
        dir,
        chunk,
    } = frame;
    let Some(inbound) = stream.inbound_mut(dir) else {
        queue_protocol_close(stream, emit);
        return;
    };
    if inbound.closed {
        queue_protocol_close(stream, emit);
    } else {
        if !chunk.bytes.is_empty() {
            emit(EngineOutput::InboundData {
                stream_id,
                dir,
                bytes: chunk.bytes,
            });
        }
        if chunk.fin && !inbound.closed {
            inbound.closed = true;
            emit(EngineOutput::InboundFinished { stream_id, dir });
        }
    }
    stream.meta.last_activity = now;
}

fn drive_stream(stream: &mut StreamState) {
    let (meta, control, role) = stream.parts_mut();
    match role {
        StreamRole::Initiator(stream) => {
            drive_stream_outbound(meta.stream_id, control, Some(&mut stream.request));
        }
        StreamRole::Responder(stream) => {
            drive_stream_outbound(meta.stream_id, control, Some(&mut stream.response));
        }
        StreamRole::Provisional(_) => drive_stream_outbound(meta.stream_id, control, None),
    }
}

fn drive_stream_outbound(
    stream_id: StreamId,
    control: &mut StreamControl,
    mut outbound: Option<&mut OutboundState>,
) {
    loop {
        if control.send_window_has_space() {
            if let Some(frame) = control.pending.pop_front() {
                enqueue_stream_frame(control, frame, 0);
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
            enqueue_stream_frame(
                control,
                StreamFrame::Data(StreamFrameData {
                    stream_id,
                    dir: outbound.dir,
                    chunk: BodyChunk {
                        bytes: Vec::new(),
                        fin: true,
                    },
                }),
                0,
            );
            continue;
        }
        return;
    }
}

fn enqueue_stream_frame(control: &mut StreamControl, frame: StreamFrame, attempt: u8) {
    let tx_seq = control.take_tx_seq();
    enqueue_stream_frame_with_seq(control, tx_seq, frame, attempt);
}

fn enqueue_stream_frame_with_seq(
    control: &mut StreamControl,
    tx_seq: StreamSeq,
    frame: StreamFrame,
    attempt: u8,
) {
    control.insert_in_flight(InFlightFrame {
        tx_seq,
        frame,
        attempt,
        write_state: InFlightWriteState::Ready,
    });
}

fn queue_protocol_close(stream: &mut StreamState, emit: &mut impl OutputFn) {
    let stream_id = stream.meta.stream_id;
    let control = &mut stream.control;
    control.clear_transient_buffers();
    control.queue_frame_front(close_frame(
        stream_id,
        CloseTarget::Both,
        CloseCode::PROTOCOL,
        Vec::new(),
    ));
    for dir in [Direction::Request, Direction::Response] {
        if let Some(outbound) = stream.outbound_mut(dir) {
            outbound.close();
            emit(EngineOutput::OutboundFailed {
                stream_id,
                dir,
                error: QlError::StreamProtocol,
            });
        }
        if let Some(inbound) = stream.inbound_mut(dir) {
            if !inbound.closed {
                inbound.closed = true;
                emit(EngineOutput::InboundFailed {
                    stream_id,
                    dir,
                    error: QlError::StreamProtocol,
                });
            }
        }
    }
    drive_stream(stream);
}

fn apply_remote_close(
    stream: &mut StreamState,
    target: CloseTarget,
    code: CloseCode,
    payload: Vec<u8>,
    emit: &mut impl OutputFn,
) {
    let stream_id = stream.meta.stream_id;
    let error = QlError::StreamClosed {
        target,
        code,
        payload: payload.clone(),
    };
    if matches!(target, CloseTarget::Request | CloseTarget::Both) {
        if let Some(inbound) = stream.inbound_mut(Direction::Request) {
            if !inbound.closed {
                inbound.closed = true;
                emit(EngineOutput::InboundFailed {
                    stream_id,
                    dir: Direction::Request,
                    error: error.clone(),
                });
            }
        }
        if let Some(outbound) = stream.outbound_mut(Direction::Request) {
            outbound.close();
            emit(EngineOutput::OutboundFailed {
                stream_id,
                dir: Direction::Request,
                error: error.clone(),
            });
        }
    }
    if matches!(target, CloseTarget::Response | CloseTarget::Both) {
        if let Some(inbound) = stream.inbound_mut(Direction::Response) {
            if !inbound.closed {
                inbound.closed = true;
                emit(EngineOutput::InboundFailed {
                    stream_id,
                    dir: Direction::Response,
                    error: error.clone(),
                });
            }
        }
        if let Some(outbound) = stream.outbound_mut(Direction::Response) {
            outbound.close();
            emit(EngineOutput::OutboundFailed {
                stream_id,
                dir: Direction::Response,
                error: error.clone(),
            });
        }
    }
}

fn apply_local_close(stream: &mut StreamState, target: CloseTarget) {
    if matches!(target, CloseTarget::Request | CloseTarget::Both) {
        if let Some(inbound) = stream.inbound_mut(Direction::Request) {
            inbound.closed = true;
        }
        if let Some(outbound) = stream.outbound_mut(Direction::Request) {
            outbound.close();
        }
    }
    if matches!(target, CloseTarget::Response | CloseTarget::Both) {
        if let Some(inbound) = stream.inbound_mut(Direction::Response) {
            inbound.closed = true;
        }
        if let Some(outbound) = stream.outbound_mut(Direction::Response) {
            outbound.close();
        }
    }
}

fn maybe_reap_stream(engine: &mut Engine, stream_id: StreamId, emit: &mut impl OutputFn) {
    if engine
        .streams
        .get(&stream_id)
        .is_some_and(StreamState::can_reap)
    {
        engine.streams.remove(&stream_id);
        emit(EngineOutput::StreamReaped { stream_id });
    }
}

fn take_next_write_for_stream(
    engine: &mut Engine,
    stream_id: StreamId,
    recipient: XID,
    session_key: &SymmetricKey,
    crypto: &impl QlCrypto,
) -> Option<OutboundWrite> {
    #[derive(Clone, Copy)]
    enum StreamWriteSelection {
        Ack,
        InitialFrame { tx_seq: StreamSeq },
        RetryFrame { tx_seq: StreamSeq },
    }

    let now = engine.state.now;
    let selection = {
        let stream = engine.streams.get(&stream_id)?;
        let is_provisional = stream.is_provisional();
        let control = &stream.control;
        if !is_provisional {
            if let Some(tx_seq) = control.in_flight.iter().find_map(|(tx_seq, in_flight)| {
                matches!(
                    in_flight.write_state,
                    InFlightWriteState::WaitingRetry { retry_at }
                        if retry_at <= now && in_flight.attempt < engine.config.stream_retry_limit
                )
                .then_some(tx_seq)
            }) {
                Some(StreamWriteSelection::RetryFrame { tx_seq })
            } else if let Some(tx_seq) = control.in_flight.iter().find_map(|(tx_seq, in_flight)| {
                matches!(in_flight.write_state, InFlightWriteState::Ready).then_some(tx_seq)
            }) {
                Some(StreamWriteSelection::InitialFrame { tx_seq })
            } else if control.ack_dirty
                && control.ack_immediate
                && control.ack_outbound_token.is_none()
            {
                Some(StreamWriteSelection::Ack)
            } else {
                None
            }
        } else if control.ack_dirty && control.ack_immediate && control.ack_outbound_token.is_none()
        {
            Some(StreamWriteSelection::Ack)
        } else {
            None
        }
    }?;

    match selection {
        StreamWriteSelection::Ack => {
            let token = engine.state.next_token();
            let ack = {
                let stream = engine.streams.get_mut(&stream_id)?;
                let control = &mut stream.control;
                if !(control.ack_dirty
                    && control.ack_immediate
                    && control.ack_outbound_token.is_none())
                {
                    return None;
                }
                let ack = control.current_ack();
                control.clear_ack_schedule();
                control.note_ack_sent(ack);
                control.ack_outbound_token = Some(token);
                ack
            };

            let body = StreamBody::Ack(StreamAckBody {
                stream_id,
                ack,
                valid_until: wire::now_secs()
                    .saturating_add(engine.config.packet_expiration.as_secs()),
            });
            let record = encrypt_stream(
                QlHeader {
                    sender: engine.identity.xid,
                    recipient,
                },
                session_key,
                &body,
                encrypted_message_nonce(crypto),
            );
            Some(engine.issue_write(
                OutboundWriteKind::StreamAck { stream_id },
                Some(token),
                wire::encode_record(&record),
            ))
        }
        StreamWriteSelection::InitialFrame { tx_seq }
        | StreamWriteSelection::RetryFrame { tx_seq } => {
            let (ack, frame) = {
                let stream = engine.streams.get_mut(&stream_id)?;
                let inbound_alive = match &stream.role {
                    StreamRole::Initiator(state) => !state.response.closed,
                    StreamRole::Responder(state) => !state.request.closed,
                    StreamRole::Provisional(_) => return None,
                };
                let control = &mut stream.control;
                let ack = control.take_piggyback_ack(inbound_alive);
                let frame = control.mark_write_issued(tx_seq)?;
                (ack, frame)
            };

            let body = StreamBody::Message(StreamMessage {
                tx_seq,
                ack,
                valid_until: wire::now_secs()
                    .saturating_add(engine.config.packet_expiration.as_secs()),
                frame,
            });
            let record = encrypt_stream(
                QlHeader {
                    sender: engine.identity.xid,
                    recipient,
                },
                session_key,
                &body,
                encrypted_message_nonce(crypto),
            );
            Some(engine.issue_write(
                OutboundWriteKind::StreamFrame { stream_id, tx_seq },
                None,
                wire::encode_record(&record),
            ))
        }
    }
}

fn close_target_for_dir(dir: Direction) -> CloseTarget {
    match dir {
        Direction::Request => CloseTarget::Request,
        Direction::Response => CloseTarget::Response,
    }
}
