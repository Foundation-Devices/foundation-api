use super::*;
use crate::{
    engine::{state::OutboundWriteKind, Engine, EngineEvent, EngineState, QlCrypto},
    stream::{StreamCloseEvent, StreamCloseKind, StreamError, StreamEventSink, WriteError},
    wire::stream::*,
};

struct EngineStreamSink<'a> {
    state: &'a mut EngineState,
}

impl EngineStreamSink<'_> {
    fn clear_active_writes_for_stream(&mut self, stream_id: StreamId) {
        self.state
            .active_writes
            .retain(|_, active| match active.kind {
                OutboundWriteKind::Control => true,
                OutboundWriteKind::Stream(completion) => completion.stream_id() != stream_id,
            });
    }

    fn emit_remote_close(&mut self, event: StreamCloseEvent) {
        let error = QlError::StreamClosed {
            target: event.frame.target,
            code: event.frame.code,
            payload: event.frame.payload,
        };

        match event.role {
            crate::stream::StreamLocalRole::Initiator => {
                if matches!(event.frame.target, CloseTarget::Request | CloseTarget::Both) {
                    self.state
                        .pending_events
                        .push_back(EngineEvent::OutboundFailed {
                            stream_id: event.frame.stream_id,
                            error: error.clone(),
                        });
                }
                if matches!(
                    event.frame.target,
                    CloseTarget::Response | CloseTarget::Both
                ) {
                    self.state
                        .pending_events
                        .push_back(EngineEvent::InboundFailed {
                            stream_id: event.frame.stream_id,
                            error,
                        });
                }
            }
            crate::stream::StreamLocalRole::Responder => {
                if matches!(event.frame.target, CloseTarget::Request | CloseTarget::Both) {
                    self.state
                        .pending_events
                        .push_back(EngineEvent::InboundFailed {
                            stream_id: event.frame.stream_id,
                            error: error.clone(),
                        });
                }
                if matches!(
                    event.frame.target,
                    CloseTarget::Response | CloseTarget::Both
                ) {
                    self.state
                        .pending_events
                        .push_back(EngineEvent::OutboundFailed {
                            stream_id: event.frame.stream_id,
                            error,
                        });
                }
            }
        }
    }

    fn emit_acked_close(&mut self, event: StreamCloseEvent) {
        let affects_outbound = match event.role {
            crate::stream::StreamLocalRole::Initiator => {
                matches!(event.frame.target, CloseTarget::Request | CloseTarget::Both)
            }
            crate::stream::StreamLocalRole::Responder => {
                matches!(
                    event.frame.target,
                    CloseTarget::Response | CloseTarget::Both
                )
            }
        };
        if !affects_outbound {
            return;
        }

        self.state
            .pending_events
            .push_back(EngineEvent::OutboundFailed {
                stream_id: event.frame.stream_id,
                error: QlError::StreamClosed {
                    target: event.frame.target,
                    code: event.frame.code,
                    payload: event.frame.payload,
                },
            });
    }
}

impl StreamEventSink for EngineStreamSink<'_> {
    fn opened(
        &mut self,
        stream_id: StreamId,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
    ) {
        self.state
            .pending_events
            .push_back(EngineEvent::InboundStreamOpened {
                stream_id,
                request_head,
                request_prefix,
            });
    }

    fn inbound_data(&mut self, stream_id: StreamId, bytes: Vec<u8>) {
        self.state
            .pending_events
            .push_back(EngineEvent::InboundData { stream_id, bytes });
    }

    fn inbound_finished(&mut self, stream_id: StreamId) {
        self.state
            .pending_events
            .push_back(EngineEvent::InboundFinished { stream_id });
    }

    fn inbound_failed(&mut self, stream_id: StreamId, error: StreamError) {
        self.state
            .pending_events
            .push_back(EngineEvent::InboundFailed {
                stream_id,
                error: stream_error(error),
            });
    }

    fn close(&mut self, event: StreamCloseEvent) {
        match event.kind {
            StreamCloseKind::Acked => self.emit_acked_close(event),
            StreamCloseKind::Remote => self.emit_remote_close(event),
        }
    }

    fn outbound_closed(&mut self, stream_id: StreamId) {
        self.state
            .pending_events
            .push_back(EngineEvent::OutboundClosed { stream_id });
    }

    fn outbound_failed(&mut self, stream_id: StreamId, error: StreamError) {
        self.state
            .pending_events
            .push_back(EngineEvent::OutboundFailed {
                stream_id,
                error: stream_error(error),
            });
    }

    fn reaped(&mut self, stream_id: StreamId) {
        self.clear_active_writes_for_stream(stream_id);
        self.state
            .pending_events
            .push_back(EngineEvent::StreamReaped { stream_id });
    }
}

pub fn open_stream(
    engine: &mut Engine,
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

    engine.sync_stream_namespace();
    Ok(engine.streams.open_stream(request_head, request_prefix))
}

pub fn handle_close_stream(
    engine: &mut Engine,
    stream_id: StreamId,
    target: CloseTarget,
    code: CloseCode,
    payload: Vec<u8>,
) -> Result<(), QlError> {
    engine
        .streams
        .close_stream(stream_id, target, code, payload)
        .map_err(stream_error)
}

pub fn handle_outbound_data(
    engine: &mut Engine,
    stream_id: StreamId,
    bytes: Vec<u8>,
) -> Result<(), QlError> {
    engine
        .streams
        .write_stream(stream_id, bytes)
        .map_err(stream_error)
}

pub fn handle_outbound_finished(engine: &mut Engine, stream_id: StreamId) -> Result<(), QlError> {
    engine
        .streams
        .finish_stream(stream_id)
        .map_err(stream_error)
}

pub fn handle_stream(
    engine: &mut Engine,
    _peer: XID,
    header: &QlHeader,
    encrypted: &mut ArchivedEncryptedMessage,
) {
    let now = engine.state.now;
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

    engine.record_activity();
    engine.sync_stream_namespace();

    let mut sink = EngineStreamSink {
        state: &mut engine.state,
    };
    engine.streams.receive(now, body, &mut sink);
}

pub fn take_next_stream_write(
    engine: &mut Engine,
    crypto: &impl QlCrypto,
) -> Option<OutboundWrite> {
    let (recipient, session_key) = engine.peer_session()?;
    engine.sync_stream_namespace();

    let outbound = engine.streams.next_outbound(
        engine.state.now,
        wire::now_secs().saturating_add(engine.config.packet_expiration.as_secs()),
    )?;
    let record = encrypt_stream(
        QlHeader {
            sender: engine.identity.xid,
            recipient,
        },
        &session_key,
        &outbound.body,
        encrypted_message_nonce(crypto),
    );

    Some(engine.issue_write(
        OutboundWriteKind::Stream(outbound.completion),
        None,
        wire::encode_record(&record),
    ))
}

pub fn complete_stream_write(
    engine: &mut Engine,
    completion: crate::stream::OutboundCompletion,
    result: Result<(), QlError>,
) {
    let now = engine.state.now;
    let mut sink = EngineStreamSink {
        state: &mut engine.state,
    };
    engine.streams.complete_outbound(
        now,
        completion,
        result.map_err(|_| WriteError::SendFailed),
        &mut sink,
    );
}

pub fn handle_stream_timeouts(engine: &mut Engine) {
    let now = engine.state.now;
    if !engine
        .streams
        .next_deadline()
        .is_some_and(|deadline| deadline <= now)
    {
        return;
    }

    let mut sink = EngineStreamSink {
        state: &mut engine.state,
    };
    engine.streams.on_timer(now, &mut sink);
}

pub fn abort_streams(engine: &mut Engine, error: QlError) {
    let mut sink = EngineStreamSink {
        state: &mut engine.state,
    };
    engine.streams.abort(stream_error_inverse(error), &mut sink);
}

fn stream_error(error: StreamError) -> QlError {
    match error {
        StreamError::MissingStream | StreamError::NotWritable => QlError::StreamProtocol,
        StreamError::SendFailed => QlError::SendFailed,
        StreamError::Timeout => QlError::Timeout,
        StreamError::Cancelled => QlError::Cancelled,
        StreamError::StreamProtocol => QlError::StreamProtocol,
    }
}

fn stream_error_inverse(error: QlError) -> StreamError {
    match error {
        QlError::SendFailed => StreamError::SendFailed,
        QlError::Timeout => StreamError::Timeout,
        QlError::Cancelled => StreamError::Cancelled,
        QlError::StreamProtocol | QlError::StreamClosed { .. } => StreamError::StreamProtocol,
        QlError::NoPeerBound
        | QlError::MissingSession
        | QlError::InvalidPayload
        | QlError::InvalidSignature => StreamError::Cancelled,
    }
}
