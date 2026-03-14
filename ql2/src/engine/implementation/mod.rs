pub mod handshake;
pub mod peer;
pub mod stream;

use std::time::{Duration, Instant};

use bc_components::{SigningPublicKey, SymmetricKey, XID};
use rkyv::access_mut;

use crate::{
    engine::{
        replay_cache::ReplayKey,
        state::{ActiveWrite, ControlWritePayload, OutboundWriteKind, TimeoutKind},
        stream::{InFlightWriteState, InitiatorAccept, ResponderResponse, StreamRole, StreamState},
        Engine, EngineInput, EngineOutput, InitiatorStage, KeepAliveConfig, KeepAliveState,
        OutboundWrite, OutputFn, PeerRecord, PeerSession, Token, WriteId,
    },
    platform::QlCrypto,
    wire::{
        self,
        encrypted_message::{ArchivedEncryptedMessage, NONCE_SIZE},
        stream::{
            encrypt_stream, Direction, ResetCode, ResetTarget, StreamBody, StreamFrame,
            StreamFrameReset, StreamMessage,
        },
        ControlMeta, QlHeader, StreamSeq,
    },
    Peer, QlError, StreamId,
};

impl Engine {
    pub fn run_tick_inner(
        &mut self,
        now: Instant,
        input: EngineInput,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        self.state.now = now;
        match input {
            EngineInput::BindPeer(peer) => peer::handle_bind_peer(self, peer, emit),
            EngineInput::Pair => peer::handle_pair_local(self, now, crypto),
            EngineInput::Connect => handshake::handle_connect(self, now, crypto, emit),
            EngineInput::Unpair => peer::handle_unpair_local(self, now, emit),
            EngineInput::OpenStream {
                open_id,
                request_head,
                request_prefix,
                config,
            } => stream::handle_open_stream(
                self,
                now,
                open_id,
                request_head,
                request_prefix,
                config,
                emit,
            ),
            EngineInput::AcceptStream {
                stream_id,
                response_head,
                response_prefix,
            } => stream::handle_accept_stream(self, now, stream_id, response_head, response_prefix),
            EngineInput::RejectStream { stream_id, code } => {
                stream::handle_reject_stream(self, now, stream_id, code)
            }
            EngineInput::OutboundData {
                stream_id,
                dir,
                bytes,
            } => stream::handle_outbound_data(self, stream_id, dir, bytes),
            EngineInput::OutboundFinished { stream_id, dir } => {
                stream::handle_outbound_finished(self, stream_id, dir)
            }
            EngineInput::ResetOutbound {
                stream_id,
                dir,
                code,
            } => stream::handle_reset_outbound(self, now, stream_id, dir, code),
            EngineInput::ResetInbound {
                stream_id,
                dir,
                code,
            } => stream::handle_reset_inbound(self, now, stream_id, dir, code),
            EngineInput::PendingAcceptDropped { stream_id } => {
                stream::handle_pending_accept_dropped(self, stream_id, emit)
            }
            EngineInput::ResponderDropped { stream_id } => {
                stream::handle_responder_dropped(self, now, stream_id)
            }
            EngineInput::Incoming(bytes) => self.handle_incoming(now, bytes, crypto, emit),
            EngineInput::TimerExpired => self.handle_timeouts(now, crypto, emit),
        }

        self.handle_ready_retransmits(now, emit);
        emit(EngineOutput::SetTimer(self.next_deadline()));
    }

    pub fn take_next_write_inner(&mut self, crypto: &impl QlCrypto) -> Option<OutboundWrite> {
        self.take_next_control_write(crypto)
            .or_else(|| stream::take_next_stream_write(self, crypto))
    }

    pub fn complete_write_inner(
        &mut self,
        write_id: WriteId,
        result: Result<(), QlError>,
        emit: &mut impl OutputFn,
    ) {
        let now = self.state.now;
        let Some(active) = self.state.active_writes.remove(&write_id) else {
            emit(EngineOutput::SetTimer(self.next_deadline()));
            return;
        };

        if let OutboundWriteKind::StreamAck { .. } = active.kind {
            if let Some(token) = active.token {
                self.clear_ack_outbound_token(token, result.is_err());
            }
        }

        if let Err(error) = result {
            if let OutboundWriteKind::StreamFrame { stream_id, .. } = active.kind {
                self.fail_stream_by_id(stream_id, error.clone(), emit);
            }

            if self.is_handshake_token(active.token) {
                if let Some(entry) = self.peer.as_mut() {
                    entry.session = PeerSession::Disconnected;
                }
                self.emit_peer_status(emit);
                self.drop_outbound();
                self.abort_streams(error, emit);
            }

            emit(EngineOutput::SetTimer(self.next_deadline()));
            return;
        }

        if let Some(session_key) = self.connected_session_for_token(active.token) {
            if let Some(entry) = self.peer.as_mut() {
                entry.session = PeerSession::Connected {
                    session_key,
                    keepalive: KeepAliveState::default(),
                };
            }
            self.emit_peer_status(emit);
            self.record_activity(now);
        }

        if let OutboundWriteKind::StreamFrame { stream_id, tx_seq } = active.kind {
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream
                    .control
                    .complete_write(tx_seq, now + self.config.stream_ack_timeout);
            }
        }

        emit(EngineOutput::SetTimer(self.next_deadline()));
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        [
            self.state.next_deadline(),
            self.streams.stream_retry_deadline(),
            self.handshake_deadline(),
            self.keep_alive_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

impl Engine {
    fn emit_peer_status(&self, emit: &mut impl OutputFn) {
        if let Some(peer) = self.peer.as_ref() {
            emit(EngineOutput::PeerStatusChanged {
                peer: peer.peer,
                session: peer.session.clone(),
            });
        }
    }

    fn next_control_meta(&self, valid_for: Duration) -> ControlMeta {
        ControlMeta {
            packet_id: self.state.next_packet_id(),
            valid_until: wire::now_secs() + valid_for.as_secs(),
        }
    }

    fn keep_alive_deadline(&self) -> Option<Instant> {
        let config = self.keep_alive_config()?;
        let entry = self.peer.as_ref()?;
        let PeerSession::Connected { keepalive, .. } = &entry.session else {
            return None;
        };
        let base = keepalive.last_activity?;
        Some(
            base + if keepalive.pending {
                config.timeout
            } else {
                config.interval
            },
        )
    }

    fn handshake_deadline(&self) -> Option<Instant> {
        let entry = self.peer.as_ref()?;
        match &entry.session {
            PeerSession::Initiator { deadline, .. } | PeerSession::Responder { deadline, .. } => {
                Some(*deadline)
            }
            PeerSession::Disconnected | PeerSession::Connected { .. } => None,
        }
    }

    fn is_replayed_control(&mut self, peer: XID, meta: ControlMeta) -> bool {
        self.state
            .replay_cache
            .check_and_store_valid_until(ReplayKey::new(peer, meta.packet_id), meta.valid_until)
    }

    // TODO: why do we pass 'now' if it's in state?
    fn handle_incoming(
        &mut self,
        now: Instant,
        mut bytes: Vec<u8>,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        let Ok(record) = access_mut::<wire::ArchivedQlRecord, rkyv::rancor::Error>(&mut bytes)
        else {
            return;
        };
        let record = unsafe { record.unseal_unchecked() };
        let sender: XID = (&record.header.sender).into();
        let recipient: XID = (&record.header.recipient).into();
        if recipient != self.identity.xid {
            return;
        }
        if !matches!(&record.payload, wire::ArchivedQlPayload::Pair(_)) {
            let Some(peer) = self.peer.as_ref().map(|peer| peer.peer) else {
                return;
            };
            if sender != peer {
                return;
            }
        }
        let Ok(header) = wire::deserialize_value(&record.header) else {
            return;
        };
        match &mut record.payload {
            wire::ArchivedQlPayload::Handshake(message) => {
                self.handle_handshake(now, sender, message, crypto, emit)
            }
            wire::ArchivedQlPayload::Stream(encrypted) => {
                stream::handle_stream(self, now, sender, &header, encrypted, emit)
            }
            wire::ArchivedQlPayload::Heartbeat(encrypted) => {
                self.handle_heartbeat(now, &header, encrypted, crypto, emit)
            }
            wire::ArchivedQlPayload::Pair(request) => {
                peer::handle_pairing(self, now, &header, request, crypto, emit)
            }
            wire::ArchivedQlPayload::Unpair(unpair_record) => {
                peer::handle_unpair(self, sender, &header, unpair_record, emit)
            }
        }
    }

    fn handle_handshake(
        &mut self,
        now: Instant,
        peer: XID,
        message: &wire::handshake::ArchivedHandshakeRecord,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        match message {
            wire::handshake::ArchivedHandshakeRecord::Hello(hello) => {
                handshake::handle_hello(self, now, peer, hello, crypto, emit)
            }
            wire::handshake::ArchivedHandshakeRecord::HelloReply(reply) => {
                handshake::handle_hello_reply(self, now, peer, reply, emit)
            }
            wire::handshake::ArchivedHandshakeRecord::Confirm(confirm) => {
                handshake::handle_confirm(self, now, peer, confirm, emit)
            }
        }
    }

    fn handle_heartbeat(
        &mut self,
        now: Instant,
        header: &QlHeader,
        encrypted: &mut ArchivedEncryptedMessage,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        let (body, should_reply) = {
            let Some(peer_record) = self.peer.as_ref() else {
                return;
            };
            let PeerSession::Connected {
                session_key,
                keepalive,
                ..
            } = &peer_record.session
            else {
                return;
            };
            let Ok(body) = wire::heartbeat::decrypt_heartbeat(header, encrypted, session_key)
            else {
                return;
            };
            (body, !keepalive.pending)
        };
        if self.is_replayed_control(header.sender, body.meta) {
            return;
        }
        self.record_activity(now);
        if should_reply {
            self.send_heartbeat_message(now, crypto);
        }
        self.emit_peer_status(emit);
    }

    fn handle_ready_retransmits(&mut self, now: Instant, emit: &mut impl OutputFn) {
        let mut timed_out = Vec::new();
        for (stream_id, stream) in self.streams.iter() {
            let exhausted = stream.control.in_flight.iter().any(|(_, in_flight)| {
                matches!(
                    in_flight.write_state,
                    InFlightWriteState::WaitingRetry { retry_at }
                        if retry_at <= now && in_flight.attempt >= self.config.stream_retry_limit
                )
            });
            if exhausted {
                timed_out.push(*stream_id);
            }
        }

        for stream_id in timed_out {
            self.fail_stream_by_id(stream_id, QlError::Timeout, emit);
        }
    }

    fn clear_ack_outbound_token(&mut self, token: Token, retry: bool) {
        for stream in self.streams.values_mut() {
            let control = &mut stream.control;
            if control.ack_outbound_token == Some(token) {
                control.ack_outbound_token = None;
                if retry {
                    control.note_ack(true);
                }
                break;
            }
        }
    }

    fn clear_active_writes_for_stream(&mut self, stream_id: StreamId) {
        self.state
            .active_writes
            .retain(|_, active| match active.kind {
                OutboundWriteKind::Control => true,
                OutboundWriteKind::StreamAck {
                    stream_id: active_stream_id,
                }
                | OutboundWriteKind::StreamReset {
                    stream_id: active_stream_id,
                } => active_stream_id != stream_id,
                OutboundWriteKind::StreamFrame {
                    stream_id: active_stream_id,
                    ..
                } => active_stream_id != stream_id,
            });
    }

    fn is_handshake_token(&self, token: Option<Token>) -> bool {
        let Some(token) = token else {
            return false;
        };
        matches!(self.peer.as_ref().map(|entry| &entry.session),
            Some(PeerSession::Initiator { handshake_token, .. }) if *handshake_token == token)
            || matches!(self.peer.as_ref().map(|entry| &entry.session),
                Some(PeerSession::Responder { handshake_token, .. }) if *handshake_token == token)
    }

    fn connected_session_for_token(&self, token: Option<Token>) -> Option<SymmetricKey> {
        let token = token?;
        self.peer.as_ref().and_then(|entry| match &entry.session {
            PeerSession::Initiator {
                session_key,
                handshake_token,
                stage: InitiatorStage::SendingConfirm,
                ..
            } if *handshake_token == token => Some(session_key.clone()),
            _ => None,
        })
    }

    fn stream_write_session(&self) -> Option<(XID, SymmetricKey)> {
        self.peer.as_ref().and_then(|peer| {
            peer.session
                .session_key()
                .map(|key| (peer.peer, key.clone()))
        })
    }

    fn issue_write(
        &mut self,
        kind: OutboundWriteKind,
        token: Option<Token>,
        bytes: Vec<u8>,
    ) -> OutboundWrite {
        let id = self.state.next_write_id();
        self.state
            .active_writes
            .insert(id, ActiveWrite { token, kind });
        OutboundWrite { id, bytes }
    }

    fn take_next_control_write(&mut self, crypto: &impl QlCrypto) -> Option<OutboundWrite> {
        while let Some(message) = self.state.control_outbound.pop_front() {
            let bytes = match message.payload {
                ControlWritePayload::Encoded(bytes) => bytes,
                ControlWritePayload::StreamReset {
                    stream_id,
                    target,
                    code,
                } => {
                    let Some((recipient, session_key)) = self.stream_write_session() else {
                        continue;
                    };
                    let body = StreamBody::Message(StreamMessage {
                        tx_seq: StreamSeq::START,
                        ack: None,
                        valid_until: wire::now_secs()
                            .saturating_add(self.config.packet_expiration.as_secs()),
                        frame: StreamFrame::Reset(StreamFrameReset {
                            stream_id,
                            target,
                            code,
                        }),
                    });
                    let record = encrypt_stream(
                        QlHeader {
                            sender: self.identity.xid,
                            recipient,
                        },
                        &session_key,
                        &body,
                        encrypted_message_nonce(crypto),
                    );
                    wire::encode_record(&record)
                }
            };
            return Some(self.issue_write(message.kind, Some(message.token), bytes));
        }
        None
    }

    fn send_ephemeral_reset(&mut self, stream_id: StreamId, dir: ResetTarget, code: ResetCode) {
        self.state
            .enqueue_stream_reset(&self.config, true, stream_id, dir, code);
    }

    fn send_heartbeat_message(&mut self, now: Instant, crypto: &impl QlCrypto) {
        let Some(peer) = self.peer.as_ref().map(|peer| peer.peer) else {
            return;
        };
        let meta = self.next_control_meta(self.config.packet_expiration);
        let token = self.state.next_token();
        let deadline = now + self.config.packet_expiration;
        let message = {
            let Some(peer_record) = self.peer.as_ref() else {
                return;
            };
            let PeerSession::Connected { session_key, .. } = &peer_record.session else {
                return;
            };
            wire::heartbeat::encrypt_heartbeat(
                QlHeader {
                    sender: self.identity.xid,
                    recipient: peer,
                },
                session_key,
                wire::heartbeat::HeartbeatBody { meta },
                encrypted_message_nonce(crypto),
            )
        };
        self.state.enqueue_handshake_message(
            &self.config,
            token,
            deadline,
            wire::encode_record(&message),
        );
    }

    fn keep_alive_config(&self) -> Option<KeepAliveConfig> {
        self.config
            .keep_alive
            .filter(|config| !config.interval.is_zero() && !config.timeout.is_zero())
    }

    fn record_activity(&mut self, now: Instant) {
        if let Some(PeerRecord {
            session: PeerSession::Connected { keepalive, .. },
            ..
        }) = self.peer.as_mut()
        {
            keepalive.last_activity = Some(now);
            keepalive.pending = false;
        }
    }

    fn drop_outbound(&mut self) {
        self.state.control_outbound.clear();
        self.state.active_writes.clear();
    }

    fn abort_streams(&mut self, error: QlError, emit: &mut impl OutputFn) {
        let streams = std::mem::take(&mut self.streams).into_inner();
        for (stream_id, stream) in streams {
            self.fail_stream(stream_id, stream, error.clone(), emit);
        }
    }

    fn fail_stream_by_id(&mut self, stream_id: StreamId, error: QlError, emit: &mut impl OutputFn) {
        let Some(stream) = self.streams.remove(&stream_id) else {
            return;
        };
        self.fail_stream(stream_id, stream, error, emit);
    }

    pub fn fail_stream(
        &mut self,
        stream_id: StreamId,
        stream: StreamState,
        error: QlError,
        emit: &mut impl OutputFn,
    ) {
        self.clear_active_writes_for_stream(stream_id);
        match stream.role {
            StreamRole::Initiator(stream) => {
                match stream.accept {
                    InitiatorAccept::Opening(waiter) | InitiatorAccept::WaitingAccept(waiter) => {
                        if let Some(open_id) = waiter.open_id {
                            emit(EngineOutput::OpenFailed {
                                open_id,
                                stream_id,
                                error: error.clone(),
                            });
                        }
                    }
                    InitiatorAccept::Open { .. } => {}
                }
                emit(EngineOutput::OutboundFailed {
                    stream_id,
                    dir: Direction::Request,
                    error: error.clone(),
                });
                emit(EngineOutput::InboundFailed {
                    stream_id,
                    dir: Direction::Response,
                    error,
                });
            }
            StreamRole::Responder(stream) => {
                emit(EngineOutput::InboundFailed {
                    stream_id,
                    dir: Direction::Request,
                    error: error.clone(),
                });
                if matches!(stream.response, ResponderResponse::Accepted { .. }) {
                    emit(EngineOutput::OutboundFailed {
                        stream_id,
                        dir: Direction::Response,
                        error,
                    });
                }
            }
            StreamRole::Provisional(_) => {}
        }
        emit(EngineOutput::StreamReaped { stream_id });
    }

    pub fn handle_timeouts(
        &mut self,
        now: Instant,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        loop {
            let Some(entry) = self
                .state
                .timeouts
                .peek_mut()
                .filter(|entry| entry.0.at <= now)
            else {
                break;
            };
            let entry = std::collections::binary_heap::PeekMut::pop(entry).0;
            match entry.kind {
                TimeoutKind::Outbound { token } => {
                    self.state
                        .control_outbound
                        .retain(|message| message.token != token);
                }
                TimeoutKind::StreamOpen { stream_id, token } => {
                    let should_fail = self
                        .streams
                        .get(&stream_id)
                        .and_then(StreamState::open_timeout_token)
                        .is_some_and(|stream_token| stream_token == token);
                    if should_fail {
                        self.fail_stream_by_id(stream_id, QlError::Timeout, emit);
                    }
                }
                TimeoutKind::StreamAckDelay { stream_id, token } => {
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        let control = &mut stream.control;
                        if control.ack_delay_token == Some(token) {
                            control.ack_delay_token = None;
                            control.ack_immediate = true;
                        }
                    }
                }
                TimeoutKind::StreamProvisional { stream_id, token } => {
                    let should_reset = self
                        .streams
                        .get(&stream_id)
                        .and_then(StreamState::provisional_timeout_token)
                        .is_some_and(|stream_token| stream_token == token);
                    if should_reset {
                        self.streams.remove(&stream_id);
                        self.send_ephemeral_reset(
                            stream_id,
                            ResetTarget::Both,
                            ResetCode::Protocol,
                        );
                    }
                }
            }
        }

        let handshake_due = self
            .handshake_deadline()
            .is_some_and(|deadline| deadline <= now);
        if handshake_due {
            if let Some(entry) = self.peer.as_mut() {
                if matches!(
                    entry.session,
                    PeerSession::Initiator { .. } | PeerSession::Responder { .. }
                ) {
                    entry.session = PeerSession::Disconnected;
                }
            }
            self.emit_peer_status(emit);
            self.drop_outbound();
            self.abort_streams(QlError::SendFailed, emit);
            return;
        }

        let keepalive_due = self
            .keep_alive_deadline()
            .is_some_and(|deadline| deadline <= now);
        if !keepalive_due {
            return;
        }

        let Some(entry) = self.peer.as_ref() else {
            return;
        };
        let PeerSession::Connected { keepalive, .. } = &entry.session else {
            return;
        };

        if keepalive.pending {
            if let Some(entry) = self.peer.as_mut() {
                entry.session = PeerSession::Disconnected;
            }
            self.emit_peer_status(emit);
            self.drop_outbound();
            self.abort_streams(QlError::SendFailed, emit);
            return;
        }

        self.send_heartbeat_message(now, crypto);
        if let Some(entry) = self.peer.as_mut() {
            if let PeerSession::Connected { keepalive, .. } = &mut entry.session {
                keepalive.pending = true;
                keepalive.last_activity = Some(now);
            }
        }
    }
}

fn encrypted_message_nonce(crypto: &impl QlCrypto) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    crypto.fill_random_bytes(&mut nonce);
    nonce
}
