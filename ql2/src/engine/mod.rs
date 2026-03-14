mod implementation;
pub mod replay_cache;
mod ring;
mod state;
mod stream;

#[cfg(test)]
mod tests;

use std::{
    cmp::Reverse,
    mem,
    time::{Duration, Instant},
};

use bc_components::{SigningPublicKey, SymmetricKey, XID};
use rkyv::access_mut;
pub use state::{
    Engine, EngineState, InitiatorStage, KeepAliveState, OpenId, OutboundWrite, PeerRecord,
    PeerSession, Token, WriteId,
};

use self::{replay_cache::ReplayKey, state::*, stream::*};
use crate::{
    platform::{QlCrypto, QlIdentity},
    wire::{
        self,
        encrypted_message::{ArchivedEncryptedMessage, NONCE_SIZE},
        handshake::{self, HandshakeRecord},
        heartbeat::{self, HeartbeatBody},
        stream::{
            decrypt_stream, encrypt_stream, BodyChunk, Direction, RejectCode, ResetCode,
            ResetTarget, StreamAck, StreamAckBody, StreamBody, StreamFrame, StreamFrameAccept,
            StreamFrameData, StreamFrameOpen, StreamFrameReject, StreamFrameReset, StreamMessage,
        },
        unpair::{self},
        ControlMeta, QlHeader, QlPayload, QlRecord, StreamSeq,
    },
    Peer, QlError, StreamId,
};

#[derive(Debug, Clone, Copy)]
pub struct KeepAliveConfig {
    pub interval: Duration,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StreamConfig {
    pub open_timeout: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
pub struct EngineConfig {
    pub handshake_timeout: Duration,
    pub default_open_timeout: Duration,
    pub packet_expiration: Duration,
    pub stream_ack_delay: Duration,
    pub stream_ack_timeout: Duration,
    pub stream_fast_retransmit_threshold: u8,
    pub stream_retry_limit: u8,
    pub keep_alive: Option<KeepAliveConfig>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
            default_open_timeout: Duration::from_secs(5),
            packet_expiration: Duration::from_secs(30),
            stream_ack_delay: Duration::from_millis(5),
            stream_ack_timeout: Duration::from_millis(150),
            stream_fast_retransmit_threshold: 2,
            stream_retry_limit: 5,
            keep_alive: None,
        }
    }
}

#[derive(Debug)]
pub enum EngineInput {
    BindPeer(Peer),
    Pair,
    Connect,
    Unpair,

    OpenStream {
        open_id: OpenId,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
        config: StreamConfig,
    },
    AcceptStream {
        stream_id: StreamId,
        response_head: Vec<u8>,
        response_prefix: Option<BodyChunk>,
    },
    RejectStream {
        stream_id: StreamId,
        code: RejectCode,
    },

    OutboundData {
        stream_id: StreamId,
        dir: Direction,
        bytes: Vec<u8>,
    },
    OutboundFinished {
        stream_id: StreamId,
        dir: Direction,
    },

    ResetOutbound {
        stream_id: StreamId,
        dir: Direction,
        code: ResetCode,
    },
    ResetInbound {
        stream_id: StreamId,
        dir: Direction,
        code: ResetCode,
    },
    PendingAcceptDropped {
        stream_id: StreamId,
    },
    ResponderDropped {
        stream_id: StreamId,
    },

    Incoming(Vec<u8>),
    TimerExpired,
}

#[derive(Debug)]
pub enum EngineOutput {
    SetTimer(Option<Instant>),

    PeerStatusChanged {
        peer: XID,
        session: PeerSession,
    },
    PersistPeer(Peer),
    ClearPeer,

    OpenStarted {
        open_id: OpenId,
        stream_id: StreamId,
    },
    OpenAccepted {
        open_id: OpenId,
        stream_id: StreamId,
        response_head: Vec<u8>,
        response_prefix: Option<BodyChunk>,
    },
    OpenFailed {
        open_id: OpenId,
        stream_id: StreamId,
        error: QlError,
    },

    InboundStreamOpened {
        stream_id: StreamId,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
    },
    InboundData {
        stream_id: StreamId,
        dir: Direction,
        bytes: Vec<u8>,
    },
    InboundFinished {
        stream_id: StreamId,
        dir: Direction,
    },
    InboundFailed {
        stream_id: StreamId,
        dir: Direction,
        error: QlError,
    },

    OutboundClosed {
        stream_id: StreamId,
        dir: Direction,
    },
    OutboundFailed {
        stream_id: StreamId,
        dir: Direction,
        error: QlError,
    },

    StreamReaped {
        stream_id: StreamId,
    },
}

pub trait OutputFn: FnMut(EngineOutput) {}

impl<T> OutputFn for T where T: FnMut(EngineOutput) {}

impl Engine {
    pub fn new(config: EngineConfig, identity: QlIdentity, peer: Option<Peer>) -> Self {
        Self {
            config: config,
            identity,
            peer: peer
                .map(|peer| PeerRecord::new(peer.peer, peer.signing_key, peer.encapsulation_key)),
            state: EngineState::new(),
            streams: StreamStore::default(),
        }
    }

    pub fn run_tick(
        &mut self,
        now: Instant,
        input: EngineInput,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        self.state.now = now;
        match input {
            EngineInput::BindPeer(peer) => self.handle_bind_peer(peer, emit),
            EngineInput::Pair => self.handle_pair_local(now, crypto),
            EngineInput::Connect => {
                implementation::handshake::handle_connect(self, now, crypto, emit)
            }
            EngineInput::Unpair => self.handle_unpair_local(now, emit),
            EngineInput::OpenStream {
                open_id,
                request_head,
                request_prefix,
                config,
            } => implementation::streams::handle_open_stream(
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
            } => implementation::streams::handle_accept_stream(
                self,
                now,
                stream_id,
                response_head,
                response_prefix,
            ),
            EngineInput::RejectStream { stream_id, code } => {
                implementation::streams::handle_reject_stream(self, now, stream_id, code)
            }
            EngineInput::OutboundData {
                stream_id,
                dir,
                bytes,
            } => implementation::streams::handle_outbound_data(self, stream_id, dir, bytes),
            EngineInput::OutboundFinished { stream_id, dir } => {
                implementation::streams::handle_outbound_finished(self, stream_id, dir)
            }
            EngineInput::ResetOutbound {
                stream_id,
                dir,
                code,
            } => implementation::streams::handle_reset_outbound(self, now, stream_id, dir, code),
            EngineInput::ResetInbound {
                stream_id,
                dir,
                code,
            } => implementation::streams::handle_reset_inbound(self, now, stream_id, dir, code),
            EngineInput::PendingAcceptDropped { stream_id } => {
                implementation::streams::handle_pending_accept_dropped(self, stream_id, emit)
            }
            EngineInput::ResponderDropped { stream_id } => {
                implementation::streams::handle_responder_dropped(self, now, stream_id)
            }
            EngineInput::Incoming(bytes) => self.handle_incoming(now, bytes, crypto, emit),
            EngineInput::TimerExpired => self.handle_timeouts(now, crypto, emit),
        }

        self.handle_ready_retransmits(now, emit);
        emit(EngineOutput::SetTimer(self.next_deadline()));
    }

    pub fn take_next_write(&mut self, crypto: &impl QlCrypto) -> Option<OutboundWrite> {
        self.take_next_control_write(crypto)
            .or_else(|| implementation::streams::take_next_stream_write(self, crypto))
    }

    pub fn complete_write(
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

    fn next_deadline(&self) -> Option<Instant> {
        [
            self.state.next_deadline(),
            self.stream_retry_deadline(),
            self.handshake_deadline(),
            self.keep_alive_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn stream_retry_deadline(&self) -> Option<Instant> {
        self.streams
            .values()
            .flat_map(|stream| {
                stream
                    .control
                    .in_flight
                    .iter()
                    .filter_map(|(_, in_flight)| match in_flight.write_state {
                        InFlightWriteState::WaitingRetry { retry_at } => Some(retry_at),
                        InFlightWriteState::Ready | InFlightWriteState::Issued => None,
                    })
            })
            .min()
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

    fn bind_peer_record(&mut self, peer: Peer, emit: &mut impl OutputFn) {
        self.reset_runtime(QlError::Cancelled, emit);
        self.peer = Some(PeerRecord::new(
            peer.peer,
            peer.signing_key,
            peer.encapsulation_key,
        ));
        self.emit_peer_status(emit);
        if let Some(peer) = self.peer.as_ref() {
            emit(EngineOutput::PersistPeer(peer.snapshot()));
        }
    }

    fn reset_runtime(&mut self, error: QlError, emit: &mut impl OutputFn) {
        let streams = mem::take(&mut self.streams).into_inner();
        for (stream_id, stream) in streams {
            self.fail_stream(stream_id, stream, error.clone(), emit);
        }
        self.state.control_outbound.clear();
        self.state.active_writes.clear();
        self.state.timeouts.clear();
    }

    fn handle_bind_peer(&mut self, peer: Peer, emit: &mut impl OutputFn) {
        if let Some(existing) = self.peer.as_ref() {
            emit(EngineOutput::PeerStatusChanged {
                peer: existing.peer,
                session: PeerSession::Disconnected,
            });
        }
        self.bind_peer_record(peer, emit);
    }

    fn handle_pair_local(&mut self, now: Instant, crypto: &impl QlCrypto) {
        let Some(peer) = self.peer.as_ref() else {
            return;
        };
        let meta = self.next_control_meta(self.config.packet_expiration);
        let Ok(record) = wire::pair::build_pair_request(
            &self.identity,
            crypto,
            peer.peer,
            &peer.encapsulation_key,
            meta,
        ) else {
            return;
        };
        let token = self.state.next_token();
        self.state.enqueue_handshake_message(
            &self.config,
            token,
            now + self.config.packet_expiration,
            wire::encode_record(&record),
        );
    }

    fn handle_unpair_local(&mut self, now: Instant, emit: &mut impl OutputFn) {
        let Some(peer) = self.peer.as_ref().map(|peer| peer.peer) else {
            return;
        };
        let meta = self.next_control_meta(self.config.packet_expiration);
        let record = unpair::build_unpair_record(
            &self.identity,
            QlHeader {
                sender: self.identity.xid,
                recipient: peer,
            },
            meta,
        );
        self.unpair_peer(emit);
        let token = self.state.next_token();
        self.state.enqueue_handshake_message(
            &self.config,
            token,
            now + self.config.packet_expiration,
            wire::encode_record(&record),
        );
    }

    // TODO: why do we pass 'now' if it's in state?
    fn handle_incoming(
        &mut self,
        now: Instant,
        mut bytes: Vec<u8>,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        let Ok(record) = access_mut::<wire::ArchivedQlRecord, wire::WireArchiveError>(&mut bytes)
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
                implementation::streams::handle_stream(self, now, sender, &header, encrypted, emit)
            }
            wire::ArchivedQlPayload::Heartbeat(encrypted) => {
                self.handle_heartbeat(now, &header, encrypted, crypto, emit)
            }
            wire::ArchivedQlPayload::Pair(request) => {
                self.handle_pairing(now, &header, request, crypto, emit)
            }
            wire::ArchivedQlPayload::Unpair(unpair_record) => {
                self.handle_unpair(sender, &header, unpair_record, emit)
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
                implementation::handshake::handle_hello(self, now, peer, hello, crypto, emit)
            }
            wire::handshake::ArchivedHandshakeRecord::HelloReply(reply) => {
                implementation::handshake::handle_hello_reply(self, now, peer, reply, emit)
            }
            wire::handshake::ArchivedHandshakeRecord::Confirm(confirm) => {
                implementation::handshake::handle_confirm(self, now, peer, confirm, emit)
            }
        }
    }

    fn handle_pairing(
        &mut self,
        now: Instant,
        header: &QlHeader,
        request: &mut wire::pair::ArchivedPairRequestRecord,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        let payload = match wire::pair::decrypt_pair_request(&self.identity, header, request) {
            Ok(payload) => payload,
            Err(_) => return,
        };
        let peer = XID::new(SigningPublicKey::MLDSA(payload.signing_pub_key.clone()));
        if self.is_replayed_control(peer, payload.meta) {
            return;
        }
        if let Some(existing) = self.peer.as_ref() {
            if existing.peer != peer
                || existing.signing_key != payload.signing_pub_key
                || existing.encapsulation_key != payload.encapsulation_pub_key
            {
                return;
            }
        } else {
            self.bind_peer_record(
                Peer {
                    peer,
                    signing_key: payload.signing_pub_key,
                    encapsulation_key: payload.encapsulation_pub_key,
                },
                emit,
            );
        }
        implementation::handshake::handle_connect(self, now, crypto, emit);
    }

    fn handle_unpair(
        &mut self,
        peer: XID,
        header: &QlHeader,
        record: &wire::unpair::ArchivedUnpairRecord,
        emit: &mut impl OutputFn,
    ) {
        {
            let Some(peer_record) = self.peer.as_ref() else {
                return;
            };
            if unpair::verify_unpair_record(header, record, &peer_record.signing_key).is_err() {
                return;
            }
        }
        let meta: ControlMeta = (&record.meta).into();
        if self.is_replayed_control(peer, meta) {
            return;
        }
        self.unpair_peer(emit);
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
            let Ok(body) = heartbeat::decrypt_heartbeat(header, encrypted, session_key) else {
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
            heartbeat::encrypt_heartbeat(
                QlHeader {
                    sender: self.identity.xid,
                    recipient: peer,
                },
                session_key,
                HeartbeatBody { meta },
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
        let streams = mem::take(&mut self.streams).into_inner();
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

    fn fail_stream(
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

    fn unpair_peer(&mut self, emit: &mut impl OutputFn) {
        let Some(peer) = self.peer.as_ref().map(|peer| peer.peer) else {
            return;
        };
        self.drop_outbound();
        self.abort_streams(QlError::SendFailed, emit);
        self.peer = None;
        emit(EngineOutput::PeerStatusChanged {
            peer,
            session: PeerSession::Disconnected,
        });
        emit(EngineOutput::ClearPeer);
    }

    fn handle_timeouts(&mut self, now: Instant, crypto: &impl QlCrypto, emit: &mut impl OutputFn) {
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
