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
    Engine, EngineInput, EngineOutput, EngineState, InitiatorStage, KeepAliveState, OpenId,
    OutboundWrite, OutputFn, PeerRecord, PeerSession, Token, WriteId,
};

use self::{replay_cache::ReplayKey, state::*, stream::*};
use crate::{
    platform::{QlCrypto, QlIdentity},
    wire::{
        self,
        encrypted_message::{ArchivedEncryptedMessage, NONCE_SIZE},
        handshake::{self, HandshakeRecord, Hello},
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

impl Engine {
    pub fn new(config: EngineConfig, identity: QlIdentity, peer: Option<Peer>) -> Self {
        Self {
            config: config,
            identity,
            state: EngineState::new(peer),
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
            EngineInput::Connect => self.handle_connect(now, crypto, emit),
            EngineInput::Unpair => self.handle_unpair_local(now, emit),
            EngineInput::OpenStream {
                open_id,
                request_head,
                request_prefix,
                config,
            } => self.handle_open_stream(now, open_id, request_head, request_prefix, config, emit),
            EngineInput::AcceptStream {
                stream_id,
                response_head,
                response_prefix,
            } => self.handle_accept_stream(now, stream_id, response_head, response_prefix),
            EngineInput::RejectStream { stream_id, code } => {
                self.handle_reject_stream(now, stream_id, code)
            }
            EngineInput::OutboundData {
                stream_id,
                dir,
                bytes,
            } => self.handle_outbound_data(stream_id, dir, bytes),
            EngineInput::OutboundFinished { stream_id, dir } => {
                self.handle_outbound_finished(stream_id, dir)
            }
            EngineInput::ResetOutbound {
                stream_id,
                dir,
                code,
            } => self.handle_reset_outbound(now, stream_id, dir, code),
            EngineInput::ResetInbound {
                stream_id,
                dir,
                code,
            } => self.handle_reset_inbound(now, stream_id, dir, code),
            EngineInput::PendingAcceptDropped { stream_id } => {
                self.handle_pending_accept_dropped(stream_id, emit)
            }
            EngineInput::ResponderDropped { stream_id } => {
                self.handle_responder_dropped(now, stream_id)
            }
            EngineInput::Incoming(bytes) => self.handle_incoming(now, bytes, crypto, emit),
            EngineInput::TimerExpired => self.handle_timeouts(now, crypto, emit),
        }

        self.handle_ready_retransmits(now, emit);
        self.drive_streams(now, emit);
        emit(EngineOutput::SetTimer(self.next_deadline()));
    }

    pub fn take_next_write(&mut self, crypto: &impl QlCrypto) -> Option<OutboundWrite> {
        self.take_next_control_write(crypto)
            .or_else(|| self.take_next_stream_write(crypto))
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
                if let Some(entry) = self.state.peer.as_mut() {
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
            if let Some(entry) = self.state.peer.as_mut() {
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
                    .control_mut()
                    .complete_write(tx_seq, now + self.config.stream_ack_timeout);
            }
        }

        emit(EngineOutput::SetTimer(self.next_deadline()));
    }

    fn emit_peer_status(&self, emit: &mut impl OutputFn) {
        if let Some(peer) = self.state.peer.as_ref() {
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
        match (self.state.next_deadline(), self.stream_retry_deadline()) {
            (Some(lhs), Some(rhs)) => Some(lhs.min(rhs)),
            (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
            (None, None) => None,
        }
    }

    fn stream_retry_deadline(&self) -> Option<Instant> {
        self.streams
            .values()
            .flat_map(|stream| {
                stream
                    .control()
                    .in_flight
                    .iter()
                    .filter_map(|(_, in_flight)| match in_flight.write_state {
                        InFlightWriteState::WaitingRetry { retry_at } => Some(retry_at),
                        InFlightWriteState::Ready | InFlightWriteState::Issued => None,
                    })
            })
            .min()
    }

    fn is_replayed_control(&mut self, peer: XID, meta: ControlMeta) -> bool {
        self.state
            .replay_cache
            .check_and_store_valid_until(ReplayKey::new(peer, meta.packet_id), meta.valid_until)
    }

    fn bind_peer_record(&mut self, peer: Peer, emit: &mut impl OutputFn) {
        self.reset_runtime(QlError::Cancelled, emit);
        self.state.peer = Some(PeerRecord::new(
            peer.peer,
            peer.signing_key,
            peer.encapsulation_key,
        ));
        self.emit_peer_status(emit);
        if let Some(peer) = self.state.peer.as_ref() {
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
        if let Some(existing) = self.state.peer.as_ref() {
            emit(EngineOutput::PeerStatusChanged {
                peer: existing.peer,
                session: PeerSession::Disconnected,
            });
        }
        self.bind_peer_record(peer, emit);
    }

    fn handle_pair_local(&mut self, now: Instant, crypto: &impl QlCrypto) {
        let Some(peer) = self.state.peer.as_ref() else {
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
        self.enqueue_handshake_message(
            token,
            now + self.config.packet_expiration,
            wire::encode_record(&record),
        );
    }

    fn handle_connect(&mut self, now: Instant, crypto: &impl QlCrypto, emit: &mut impl OutputFn) {
        let Some(peer_record) = self.state.peer.as_ref() else {
            return;
        };
        let peer = peer_record.peer;
        let meta = self.next_control_meta(self.config.handshake_timeout);
        let (hello, session_key) = match &peer_record.session {
            PeerSession::Connected { .. }
            | PeerSession::Initiator { .. }
            | PeerSession::Responder { .. } => {
                return;
            }
            PeerSession::Disconnected => {
                match handshake::build_hello(
                    &self.identity,
                    crypto,
                    peer,
                    &peer_record.encapsulation_key,
                    meta,
                ) {
                    Ok(result) => result,
                    Err(_) => return,
                }
            }
        };

        let deadline = now + self.config.handshake_timeout;
        let token = self.state.next_token();
        if let Some(entry) = self.state.peer.as_mut() {
            entry.session = PeerSession::Initiator {
                handshake_token: token,
                hello: hello.clone(),
                session_key,
                deadline,
                stage: InitiatorStage::WaitingHelloReply,
            };
        }
        self.emit_peer_status(emit);

        let record = QlRecord {
            header: QlHeader {
                sender: self.identity.xid,
                recipient: peer,
            },
            payload: QlPayload::Handshake(HandshakeRecord::Hello(hello)),
        };
        self.enqueue_handshake_message(token, deadline, wire::encode_record(&record));
    }

    fn handle_unpair_local(&mut self, now: Instant, emit: &mut impl OutputFn) {
        let Some(peer) = self.state.peer.as_ref().map(|peer| peer.peer) else {
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
        self.enqueue_handshake_message(
            token,
            now + self.config.packet_expiration,
            wire::encode_record(&record),
        );
    }

    fn handle_open_stream(
        &mut self,
        now: Instant,
        open_id: OpenId,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
        config: StreamConfig,
        emit: &mut impl OutputFn,
    ) {
        let Some(entry) = self.state.peer.as_ref() else {
            emit(EngineOutput::OpenFailed {
                open_id,
                stream_id: StreamId(0),
                error: QlError::NoPeerBound,
            });
            return;
        };
        if !entry.session.is_connected() {
            emit(EngineOutput::OpenFailed {
                open_id,
                stream_id: StreamId(0),
                error: QlError::MissingSession,
            });
            return;
        }

        let stream_namespace = StreamNamespace::for_local(self.identity.xid, entry.peer);
        let stream_id = self.state.next_stream_id(stream_namespace);
        let open_timeout = config
            .open_timeout
            .unwrap_or(self.config.default_open_timeout);
        let token = self.state.next_token();
        let request_prefix_fin = request_prefix.as_ref().is_some_and(|chunk| chunk.fin);
        let frame = StreamFrameOpen {
            stream_id,
            request_head,
            request_prefix,
        };
        let stream = StreamState::Initiator(InitiatorStream {
            meta: StreamMeta {
                stream_id,
                last_activity: now,
            },
            control: StreamControl {
                pending: std::collections::VecDeque::from([StreamFrame::Open(frame)]),
                ..Default::default()
            },
            request: OutboundState::from_prefix(Direction::Request, request_prefix_fin),
            response: InboundState::new(),
            accept: InitiatorAccept::Opening(OpenWaiter {
                open_id: Some(open_id),
                open_timeout_token: token,
            }),
        });
        self.streams.insert(stream_id, stream);
        self.state.timeouts.push(Reverse(TimeoutEntry {
            at: now + open_timeout,
            kind: TimeoutKind::StreamOpen { stream_id, token },
        }));
        emit(EngineOutput::OpenStarted { open_id, stream_id });
    }

    fn handle_accept_stream(
        &mut self,
        now: Instant,
        stream_id: StreamId,
        response_head: Vec<u8>,
        response_prefix: Option<BodyChunk>,
    ) {
        let Some(StreamState::Responder(stream)) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let ResponderResponse::Pending = stream.response else {
            return;
        };
        let response_prefix_fin = response_prefix.as_ref().is_some_and(|chunk| chunk.fin);
        stream
            .control
            .pending
            .push_back(StreamFrame::Accept(StreamFrameAccept {
                stream_id,
                response_head,
                response_prefix,
            }));
        stream.response = ResponderResponse::Accepted {
            body: OutboundState::from_prefix(Direction::Response, response_prefix_fin),
        };
        stream.meta.last_activity = now;
    }

    fn handle_reject_stream(&mut self, now: Instant, stream_id: StreamId, code: RejectCode) {
        let Some(StreamState::Responder(stream)) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let ResponderResponse::Pending = stream.response else {
            return;
        };
        stream
            .control
            .pending
            .push_back(StreamFrame::Reject(StreamFrameReject { stream_id, code }));
        stream.response = ResponderResponse::Rejecting;
        stream.meta.last_activity = now;
    }

    fn handle_outbound_data(&mut self, stream_id: StreamId, dir: Direction, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let Some(outbound) = stream.outbound_mut(dir) else {
            return;
        };
        if !outbound.take_pending_pull() {
            return;
        }
        let chunk = BodyChunk { bytes, fin: false };
        stream
            .control_mut()
            .queue_frame_back(StreamFrame::Data(StreamFrameData {
                stream_id,
                dir,
                chunk,
            }));
    }

    fn handle_outbound_finished(&mut self, stream_id: StreamId, dir: Direction) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let Some(outbound) = stream.outbound_mut(dir) else {
            return;
        };
        outbound.finish();
    }

    fn handle_reset_outbound(
        &mut self,
        now: Instant,
        stream_id: StreamId,
        dir: Direction,
        code: ResetCode,
    ) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let Some(outbound) = stream.outbound_mut(dir) else {
            return;
        };
        if outbound.is_closed() {
            return;
        }
        outbound.close();
        stream.control_mut().queue_frame_front(reset_frame(
            stream_id,
            reset_target_for_dir(dir),
            code,
        ));
        *stream.last_activity_mut() = now;
    }

    fn handle_reset_inbound(
        &mut self,
        now: Instant,
        stream_id: StreamId,
        dir: Direction,
        code: ResetCode,
    ) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let Some(inbound) = stream.inbound_mut(dir) else {
            return;
        };
        if inbound.closed {
            return;
        }
        inbound.closed = true;
        stream.control_mut().queue_frame_front(reset_frame(
            stream_id,
            reset_target_for_dir(dir),
            code,
        ));
        *stream.last_activity_mut() = now;
    }

    fn handle_responder_dropped(&mut self, now: Instant, stream_id: StreamId) {
        self.handle_reject_stream(now, stream_id, RejectCode::Unhandled);
    }

    fn handle_pending_accept_dropped(&mut self, stream_id: StreamId, emit: &mut impl OutputFn) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        if let StreamState::Initiator(stream) = stream {
            match &mut stream.accept {
                InitiatorAccept::Opening(waiter) | InitiatorAccept::WaitingAccept(waiter) => {
                    waiter.open_id = None;
                }
                InitiatorAccept::Open { .. } => {}
            }
        }
        self.maybe_reap_stream(stream_id, emit);
    }

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
            let Some(peer) = self.state.peer.as_ref().map(|peer| peer.peer) else {
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
                self.handle_stream(now, sender, &header, encrypted, emit)
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
                self.handle_hello(now, peer, hello, crypto, emit)
            }
            wire::handshake::ArchivedHandshakeRecord::HelloReply(reply) => {
                self.handle_hello_reply(now, peer, reply, emit)
            }
            wire::handshake::ArchivedHandshakeRecord::Confirm(confirm) => {
                self.handle_confirm(now, peer, confirm, emit)
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
        if let Some(existing) = self.state.peer.as_ref() {
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
        self.handle_connect(now, crypto, emit);
    }

    fn handle_unpair(
        &mut self,
        peer: XID,
        header: &QlHeader,
        record: &wire::unpair::ArchivedUnpairRecord,
        emit: &mut impl OutputFn,
    ) {
        {
            let Some(peer_record) = self.state.peer.as_ref() else {
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
            let Some(peer_record) = self.state.peer.as_ref() else {
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

    fn handle_stream(
        &mut self,
        now: Instant,
        _peer: XID,
        header: &QlHeader,
        encrypted: &mut ArchivedEncryptedMessage,
        emit: &mut impl OutputFn,
    ) {
        let body = {
            let Some(peer_record) = self.state.peer.as_ref() else {
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

        let message = match body {
            StreamBody::Ack(StreamAckBody { stream_id, ack, .. }) => {
                self.process_stream_ack(now, stream_id, ack, emit);
                self.record_activity(now);
                self.record_stream_activity(stream_id, now);
                self.maybe_reap_stream(stream_id, emit);
                return;
            }
            StreamBody::Message(message) => message,
        };

        let stream_id = message.frame.stream_id();
        if let Some(ack) = message.ack {
            self.process_stream_ack(now, stream_id, ack, emit);
        }

        if !self.streams.contains_key(&stream_id) {
            let Some(peer_record) = self.state.peer.as_ref() else {
                return;
            };
            let local_namespace = StreamNamespace::for_local(self.identity.xid, peer_record.peer);
            if !local_namespace.remote().matches(stream_id) {
                return;
            }
            let token = self.state.next_token();
            self.streams.insert(
                stream_id,
                StreamState::Provisional(ProvisionalStream {
                    meta: StreamMeta {
                        stream_id,
                        last_activity: now,
                    },
                    control: StreamControl::default(),
                    timeout_token: token,
                }),
            );
            self.state.timeouts.push(Reverse(TimeoutEntry {
                at: now + self.config.default_open_timeout,
                kind: TimeoutKind::StreamProvisional { stream_id, token },
            }));
        }

        let buffer_result = {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return;
            };
            *stream.last_activity_mut() = now;
            stream
                .control_mut()
                .buffer_incoming(message.tx_seq, message.frame)
        };

        match buffer_result {
            BufferIncomingResult::OutOfWindow => {
                if self
                    .streams
                    .get(&stream_id)
                    .is_some_and(StreamState::is_provisional)
                {
                    self.streams.remove(&stream_id);
                    self.send_ephemeral_reset(stream_id, ResetTarget::Both, ResetCode::Protocol);
                } else if let Some(stream) = self.streams.get_mut(&stream_id) {
                    Self::queue_protocol_reset(stream, emit);
                    *stream.last_activity_mut() = now;
                }
                return;
            }
            BufferIncomingResult::Duplicate | BufferIncomingResult::AlreadyBuffered => {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.control_mut().note_ack(true);
                }
                self.schedule_stream_ack(stream_id, now);
                self.record_activity(now);
                self.record_stream_activity(stream_id, now);
                return;
            }
            BufferIncomingResult::Buffered { out_of_order } => {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.control_mut().note_ack(out_of_order);
                }
            }
        }
        self.record_activity(now);
        self.record_stream_activity(stream_id, now);
        self.drain_committed_stream_frames(now, stream_id, emit);
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.control_mut().maybe_force_ack_for_progress();
        }
        self.schedule_stream_ack(stream_id, now);
    }

    fn schedule_stream_ack(&mut self, stream_id: StreamId, now: Instant) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let control = stream.control_mut();
        if !control.ack_dirty {
            return;
        }
        if control.ack_immediate || self.config.stream_ack_delay.is_zero() {
            control.ack_delay_token = None;
            return;
        }
        if control.ack_delay_token.is_some() {
            return;
        }
        let token = self.state.next_token();
        control.ack_delay_token = Some(token);
        self.state.timeouts.push(Reverse(TimeoutEntry {
            at: now + self.config.stream_ack_delay,
            kind: TimeoutKind::StreamAckDelay { stream_id, token },
        }));
    }

    fn drain_committed_stream_frames(
        &mut self,
        now: Instant,
        stream_id: StreamId,
        emit: &mut impl OutputFn,
    ) {
        loop {
            let next = {
                let Some(stream) = self.streams.get_mut(&stream_id) else {
                    return;
                };
                stream.control_mut().pop_next_committable()
            };
            let Some((_tx_seq, frame)) = next else {
                break;
            };
            if self
                .streams
                .get(&stream_id)
                .is_some_and(StreamState::is_provisional)
                && !matches!(frame, StreamFrame::Open(_))
            {
                self.streams.remove(&stream_id);
                self.send_ephemeral_reset(stream_id, ResetTarget::Both, ResetCode::Protocol);
                return;
            }
            match frame {
                StreamFrame::Open(frame) => self.handle_stream_open(now, frame, emit),
                StreamFrame::Accept(frame) => self.handle_stream_accept_from_peer(now, frame, emit),
                StreamFrame::Reject(frame) => self.handle_stream_reject_from_peer(frame, emit),
                StreamFrame::Data(frame) => self.handle_stream_data(now, frame, emit),
                StreamFrame::Reset(frame) => self.handle_stream_reset(now, frame, emit),
            }
            if !self.streams.contains_key(&stream_id) {
                return;
            }
        }
        self.maybe_reap_stream(stream_id, emit);
    }

    fn handle_stream_open(
        &mut self,
        now: Instant,
        frame: StreamFrameOpen,
        emit: &mut impl OutputFn,
    ) {
        let StreamFrameOpen {
            stream_id,
            request_head,
            request_prefix,
        } = frame;
        let control = match self.streams.remove(&stream_id) {
            Some(StreamState::Provisional(stream)) => stream.control,
            Some(mut stream) => {
                Self::queue_protocol_reset(&mut stream, emit);
                self.streams.insert(stream_id, stream);
                return;
            }
            None => StreamControl::default(),
        };

        let mut stream = StreamState::Responder(ResponderStream {
            meta: StreamMeta {
                stream_id,
                last_activity: now,
            },
            control,
            request: InboundState::new(),
            response: ResponderResponse::Pending,
        });
        if let Some(chunk) = request_prefix.as_ref() {
            let Some(inbound) = stream.inbound_mut(Direction::Request) else {
                return;
            };
            if chunk.fin {
                inbound.closed = true;
            }
        }
        self.streams.insert(stream_id, stream);
        emit(EngineOutput::InboundStreamOpened {
            stream_id,
            request_head,
            request_prefix,
        });
    }

    fn handle_stream_accept_from_peer(
        &mut self,
        now: Instant,
        frame: StreamFrameAccept,
        emit: &mut impl OutputFn,
    ) {
        let StreamFrameAccept {
            stream_id,
            response_head,
            response_prefix,
        } = frame;
        let mut protocol = false;
        let mut response_prefix_output = None;
        {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return;
            };
            match stream {
                StreamState::Initiator(stream) => match &mut stream.accept {
                    InitiatorAccept::Opening(waiter) => {
                        if let Some(open_id) = waiter.open_id.take() {
                            emit(EngineOutput::OpenAccepted {
                                open_id,
                                stream_id,
                                response_head: response_head.clone(),
                                response_prefix: response_prefix.clone(),
                            });
                        } else {
                            stream.response.closed = true;
                            stream.control.queue_frame_front(reset_frame(
                                stream_id,
                                ResetTarget::Response,
                                ResetCode::Cancelled,
                            ));
                        }
                        stream.accept = InitiatorAccept::Open { response_head };
                        stream.meta.last_activity = now;
                        response_prefix_output = response_prefix.clone();
                    }
                    InitiatorAccept::WaitingAccept(waiter) => {
                        if let Some(open_id) = waiter.open_id.take() {
                            emit(EngineOutput::OpenAccepted {
                                open_id,
                                stream_id,
                                response_head: response_head.clone(),
                                response_prefix: response_prefix.clone(),
                            });
                        } else {
                            stream.response.closed = true;
                            stream.control.queue_frame_front(reset_frame(
                                stream_id,
                                ResetTarget::Response,
                                ResetCode::Cancelled,
                            ));
                        }
                        stream.accept = InitiatorAccept::Open { response_head };
                        stream.meta.last_activity = now;
                        response_prefix_output = response_prefix.clone();
                    }
                    InitiatorAccept::Open {
                        response_head: stored,
                    } => {
                        if *stored != response_head {
                            protocol = true;
                        }
                    }
                },
                _ => protocol = true,
            }
        }

        if protocol {
            self.send_ephemeral_reset(stream_id, ResetTarget::Both, ResetCode::Protocol);
            return;
        }

        if let Some(chunk) = response_prefix_output.as_ref() {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return;
            };
            let Some(inbound) = stream.inbound_mut(Direction::Response) else {
                Self::queue_protocol_reset(stream, emit);
                return;
            };
            if chunk.fin && !inbound.closed {
                inbound.closed = true;
                self.maybe_reap_stream(stream_id, emit);
            }
        }
    }

    fn handle_stream_reject_from_peer(
        &mut self,
        frame: StreamFrameReject,
        emit: &mut impl OutputFn,
    ) {
        let StreamFrameReject { stream_id, code } = frame;
        let mut protocol = false;
        let mut remove_after = false;
        {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return;
            };
            match stream {
                StreamState::Initiator(stream) => match &mut stream.accept {
                    InitiatorAccept::Opening(waiter) | InitiatorAccept::WaitingAccept(waiter) => {
                        if let Some(open_id) = waiter.open_id.take() {
                            emit(EngineOutput::OpenFailed {
                                open_id,
                                stream_id,
                                error: QlError::StreamRejected { code },
                            });
                        }
                        emit(EngineOutput::OutboundClosed {
                            stream_id,
                            dir: Direction::Request,
                        });
                        emit(EngineOutput::InboundFailed {
                            stream_id,
                            dir: Direction::Response,
                            error: QlError::StreamRejected { code },
                        });
                        stream.request.close();
                        stream.response.closed = true;
                        remove_after = true;
                    }
                    InitiatorAccept::Open { .. } => protocol = true,
                },
                _ => protocol = true,
            }
        }
        if remove_after {
            self.streams.remove(&stream_id);
            emit(EngineOutput::StreamReaped { stream_id });
        }
        if protocol {
            self.send_ephemeral_reset(stream_id, ResetTarget::Both, ResetCode::Protocol);
        }
    }

    fn handle_stream_data(
        &mut self,
        now: Instant,
        frame: StreamFrameData,
        emit: &mut impl OutputFn,
    ) {
        let StreamFrameData {
            stream_id,
            dir,
            chunk,
        } = frame;
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        if dir == Direction::Response
            && matches!(
                stream,
                StreamState::Initiator(InitiatorStream {
                    accept: InitiatorAccept::Opening(_) | InitiatorAccept::WaitingAccept(_),
                    ..
                })
            )
        {
            Self::queue_protocol_reset(stream, emit);
            *stream.last_activity_mut() = now;
            return;
        }
        let Some(inbound) = stream.inbound_mut(dir) else {
            Self::queue_protocol_reset(stream, emit);
            return;
        };
        if inbound.closed {
            Self::queue_protocol_reset(stream, emit);
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
        *stream.last_activity_mut() = now;
        self.maybe_reap_stream(stream_id, emit);
    }

    fn handle_stream_reset(
        &mut self,
        now: Instant,
        frame: StreamFrameReset,
        emit: &mut impl OutputFn,
    ) {
        let StreamFrameReset {
            stream_id,
            target,
            code,
        } = frame;
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        Self::apply_remote_reset(stream, target, code, emit);
        *stream.last_activity_mut() = now;
        self.maybe_reap_stream(stream_id, emit);
    }

    fn process_stream_ack(
        &mut self,
        now: Instant,
        stream_id: StreamId,
        ack: StreamAck,
        emit: &mut impl OutputFn,
    ) {
        let should_reap = {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return;
            };
            stream.control_mut().clear_fast_recovery(ack.base);
            let fast_retransmit = stream
                .control()
                .fast_retransmit_candidate(ack, self.config.stream_fast_retransmit_threshold);

            loop {
                let acked_tx_seq = stream
                    .control()
                    .in_flight
                    .iter()
                    .map(|(tx_seq, _)| tx_seq)
                    .find(|tx_seq| StreamControl::ack_covers(ack, *tx_seq));
                let Some(tx_seq) = acked_tx_seq else {
                    break;
                };
                let Some(in_flight) = stream.control_mut().remove_in_flight(tx_seq) else {
                    continue;
                };

                match in_flight.frame {
                    StreamFrame::Open(StreamFrameOpen { request_prefix, .. }) => {
                        if let StreamState::Initiator(stream) = stream {
                            if let InitiatorAccept::Opening(waiter) = &stream.accept {
                                stream.accept = InitiatorAccept::WaitingAccept(OpenWaiter {
                                    open_id: waiter.open_id,
                                    open_timeout_token: waiter.open_timeout_token,
                                });
                            }
                            if request_prefix.as_ref().is_some_and(|chunk| chunk.fin) {
                                stream.request.close();
                                emit(EngineOutput::OutboundClosed {
                                    stream_id,
                                    dir: Direction::Request,
                                });
                            }
                        }
                    }
                    StreamFrame::Accept(StreamFrameAccept {
                        response_prefix, ..
                    }) => {
                        if let StreamState::Responder(stream) = stream {
                            if response_prefix.as_ref().is_some_and(|chunk| chunk.fin) {
                                if let ResponderResponse::Accepted { body } = &mut stream.response {
                                    body.close();
                                    emit(EngineOutput::OutboundClosed {
                                        stream_id,
                                        dir: Direction::Response,
                                    });
                                }
                            }
                        }
                    }
                    StreamFrame::Reject(_) => {}
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
                    StreamFrame::Reset(StreamFrameReset { target, code, .. }) => {
                        for outbound_dir in [Direction::Request, Direction::Response] {
                            let affects_outbound = matches!(
                                (target, outbound_dir),
                                (ResetTarget::Request, Direction::Request)
                                    | (ResetTarget::Response, Direction::Response)
                                    | (ResetTarget::Both, _)
                            );
                            if affects_outbound {
                                if let Some(outbound) = stream.outbound_mut(outbound_dir) {
                                    outbound.close();
                                    emit(EngineOutput::OutboundFailed {
                                        stream_id,
                                        dir: outbound_dir,
                                        error: QlError::StreamReset {
                                            dir: outbound_dir,
                                            code,
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
                stream.control_mut().schedule_fast_retransmit(tx_seq, now);
            }
            stream.can_reap()
        };

        if should_reap {
            self.streams.remove(&stream_id);
            emit(EngineOutput::StreamReaped { stream_id });
        }
    }

    fn drive_streams(&mut self, now: Instant, emit: &mut impl OutputFn) {
        for stream in self.streams.values_mut() {
            Self::drive_stream(now, stream, emit);
        }
    }

    fn drive_stream(_now: Instant, stream: &mut StreamState, emit: &mut impl OutputFn) {
        match stream {
            StreamState::Initiator(stream) => {
                Self::drive_stream_outbound(
                    stream.meta.stream_id,
                    &mut stream.control,
                    Some(&mut stream.request),
                    emit,
                );
            }
            StreamState::Responder(stream) => {
                let stream_id = stream.meta.stream_id;
                match &mut stream.response {
                    ResponderResponse::Accepted { body, .. } => {
                        Self::drive_stream_outbound(
                            stream_id,
                            &mut stream.control,
                            Some(body),
                            emit,
                        );
                    }
                    _ => {
                        Self::drive_stream_outbound(stream_id, &mut stream.control, None, emit);
                    }
                }
            }
            StreamState::Provisional(stream) => {
                Self::drive_stream_outbound(stream.meta.stream_id, &mut stream.control, None, emit)
            }
        }
    }

    fn drive_stream_outbound(
        stream_id: StreamId,
        control: &mut StreamControl,
        mut outbound: Option<&mut OutboundState>,
        emit: &mut impl OutputFn,
    ) {
        loop {
            if control.send_window_has_space() {
                if let Some(frame) = control.pending.pop_front() {
                    Self::enqueue_stream_frame(control, frame, 0);
                    continue;
                }
            }
            if !control.send_window_has_space() {
                return;
            }

            let Some(outbound) = outbound.as_deref_mut() else {
                return;
            };
            if outbound.request_data() {
                emit(EngineOutput::NeedOutboundData {
                    stream_id,
                    dir: outbound.dir,
                });
                return;
            }
            if outbound.queue_fin() {
                Self::enqueue_stream_frame(
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
        Self::enqueue_stream_frame_with_seq(control, tx_seq, frame, attempt);
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

    fn queue_protocol_reset(stream: &mut StreamState, emit: &mut impl OutputFn) {
        let stream_id = stream.stream_id();
        let control = stream.control_mut();
        control.clear_transient_buffers();
        control.queue_frame_front(reset_frame(
            stream_id,
            ResetTarget::Both,
            ResetCode::Protocol,
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
        if let StreamState::Initiator(stream) = stream {
            match &mut stream.accept {
                InitiatorAccept::Opening(waiter) | InitiatorAccept::WaitingAccept(waiter) => {
                    if let Some(open_id) = waiter.open_id.take() {
                        emit(EngineOutput::OpenFailed {
                            open_id,
                            stream_id,
                            error: QlError::StreamProtocol,
                        });
                    }
                }
                InitiatorAccept::Open { .. } => {}
            }
        }
    }

    fn apply_remote_reset(
        stream: &mut StreamState,
        target: ResetTarget,
        code: ResetCode,
        emit: &mut impl OutputFn,
    ) {
        let stream_id = stream.stream_id();
        let request_error = QlError::StreamReset {
            dir: Direction::Request,
            code,
        };
        let response_error = QlError::StreamReset {
            dir: Direction::Response,
            code,
        };

        if matches!(target, ResetTarget::Request | ResetTarget::Both) {
            if let Some(inbound) = stream.inbound_mut(Direction::Request) {
                if !inbound.closed {
                    inbound.closed = true;
                    emit(EngineOutput::InboundFailed {
                        stream_id,
                        dir: Direction::Request,
                        error: request_error.clone(),
                    });
                }
            }
            if let Some(outbound) = stream.outbound_mut(Direction::Request) {
                outbound.close();
                emit(EngineOutput::OutboundFailed {
                    stream_id,
                    dir: Direction::Request,
                    error: request_error.clone(),
                });
            }
        }
        if matches!(target, ResetTarget::Response | ResetTarget::Both) {
            if let Some(inbound) = stream.inbound_mut(Direction::Response) {
                if !inbound.closed {
                    inbound.closed = true;
                    emit(EngineOutput::InboundFailed {
                        stream_id,
                        dir: Direction::Response,
                        error: response_error.clone(),
                    });
                }
            }
            if let Some(outbound) = stream.outbound_mut(Direction::Response) {
                outbound.close();
                emit(EngineOutput::OutboundFailed {
                    stream_id,
                    dir: Direction::Response,
                    error: response_error.clone(),
                });
            }
        }

        if let StreamState::Initiator(stream) = stream {
            match &mut stream.accept {
                InitiatorAccept::Opening(waiter) | InitiatorAccept::WaitingAccept(waiter) => {
                    if let Some(open_id) = waiter.open_id.take() {
                        emit(EngineOutput::OpenFailed {
                            open_id,
                            stream_id,
                            error: match target {
                                ResetTarget::Request => request_error,
                                _ => response_error,
                            },
                        });
                    }
                }
                InitiatorAccept::Open { .. } => {}
            }
        }
    }

    fn maybe_reap_stream(&mut self, stream_id: StreamId, emit: &mut impl OutputFn) {
        if self
            .streams
            .get(&stream_id)
            .is_some_and(StreamState::can_reap)
        {
            self.streams.remove(&stream_id);
            emit(EngineOutput::StreamReaped { stream_id });
        }
    }

    fn handle_ready_retransmits(&mut self, now: Instant, emit: &mut impl OutputFn) {
        let mut timed_out = Vec::new();
        for (stream_id, stream) in self.streams.iter() {
            let exhausted = stream.control().in_flight.iter().any(|(_, in_flight)| {
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
            let control = stream.control_mut();
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
        matches!(self.state.peer.as_ref().map(|entry| &entry.session),
            Some(PeerSession::Initiator { handshake_token, .. }) if *handshake_token == token)
            || matches!(self.state.peer.as_ref().map(|entry| &entry.session),
                Some(PeerSession::Responder { handshake_token, .. }) if *handshake_token == token)
    }

    fn connected_session_for_token(&self, token: Option<Token>) -> Option<SymmetricKey> {
        let token = token?;
        self.state
            .peer
            .as_ref()
            .and_then(|entry| match &entry.session {
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
        self.state.peer.as_ref().and_then(|peer| {
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

    fn take_next_stream_write(&mut self, crypto: &impl QlCrypto) -> Option<OutboundWrite> {
        let (recipient, session_key) = self.stream_write_session()?;
        let stream_ids: Vec<_> = self.streams.scan_from_cursor().collect();
        for stream_id in stream_ids {
            let write = self.take_next_write_for_stream(stream_id, recipient, &session_key, crypto);
            if write.is_some() {
                self.streams.advance_cursor_after(stream_id);
                return write;
            }
        }
        None
    }

    fn take_next_write_for_stream(
        &mut self,
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

        let now = self.state.now;
        let selection = {
            let stream = self.streams.get(&stream_id)?;
            let is_provisional = matches!(stream, StreamState::Provisional(_));
            let control = stream.control();
            if !is_provisional {
                if let Some(tx_seq) = control.in_flight.iter().find_map(|(tx_seq, in_flight)| {
                    matches!(
                        in_flight.write_state,
                        InFlightWriteState::WaitingRetry { retry_at }
                            if retry_at <= now && in_flight.attempt < self.config.stream_retry_limit
                    )
                    .then_some(tx_seq)
                }) {
                    Some(StreamWriteSelection::RetryFrame { tx_seq })
                } else if let Some(tx_seq) =
                    control.in_flight.iter().find_map(|(tx_seq, in_flight)| {
                        matches!(in_flight.write_state, InFlightWriteState::Ready).then_some(tx_seq)
                    })
                {
                    Some(StreamWriteSelection::InitialFrame { tx_seq })
                } else if control.ack_dirty
                    && control.ack_immediate
                    && control.ack_outbound_token.is_none()
                {
                    Some(StreamWriteSelection::Ack)
                } else {
                    None
                }
            } else if control.ack_dirty
                && control.ack_immediate
                && control.ack_outbound_token.is_none()
            {
                Some(StreamWriteSelection::Ack)
            } else {
                None
            }
        }?;

        match selection {
            StreamWriteSelection::Ack => {
                let token = self.state.next_token();
                let ack = {
                    let stream = self.streams.get_mut(&stream_id)?;
                    let control = stream.control_mut();
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
                        .saturating_add(self.config.packet_expiration.as_secs()),
                });
                let record = encrypt_stream(
                    QlHeader {
                        sender: self.identity.xid,
                        recipient,
                    },
                    session_key,
                    &body,
                    encrypted_message_nonce(crypto),
                );
                Some(self.issue_write(
                    OutboundWriteKind::StreamAck { stream_id },
                    Some(token),
                    wire::encode_record(&record),
                ))
            }
            StreamWriteSelection::InitialFrame { tx_seq }
            | StreamWriteSelection::RetryFrame { tx_seq } => {
                let (ack, frame) = {
                    let stream = self.streams.get_mut(&stream_id)?;
                    match stream {
                        StreamState::Initiator(state) => {
                            let ack = state.control.take_piggyback_ack(!state.response.closed);
                            let frame = state.control.mark_write_issued(tx_seq)?;
                            (ack, frame)
                        }
                        StreamState::Responder(state) => {
                            let ack = state.control.take_piggyback_ack(!state.request.closed);
                            let frame = state.control.mark_write_issued(tx_seq)?;
                            (ack, frame)
                        }
                        StreamState::Provisional(_) => return None,
                    }
                };

                let body = StreamBody::Message(StreamMessage {
                    tx_seq,
                    ack,
                    valid_until: wire::now_secs()
                        .saturating_add(self.config.packet_expiration.as_secs()),
                    frame,
                });
                let record = encrypt_stream(
                    QlHeader {
                        sender: self.identity.xid,
                        recipient,
                    },
                    session_key,
                    &body,
                    encrypted_message_nonce(crypto),
                );
                Some(self.issue_write(
                    OutboundWriteKind::StreamFrame { stream_id, tx_seq },
                    None,
                    wire::encode_record(&record),
                ))
            }
        }
    }

    fn send_ephemeral_reset(&mut self, stream_id: StreamId, dir: ResetTarget, code: ResetCode) {
        self.state
            .enqueue_stream_reset(&self.config, true, stream_id, dir, code);
    }

    fn enqueue_handshake_message(&mut self, token: Token, deadline: Instant, bytes: Vec<u8>) {
        self.state
            .enqueue_handshake_message(&self.config, token, deadline, bytes);
    }

    fn handle_hello(
        &mut self,
        now: Instant,
        peer: XID,
        hello: &wire::handshake::ArchivedHello,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        let action = match self.state.peer.as_ref() {
            Some(entry) => {
                if handshake::verify_hello(peer, self.identity.xid, &entry.signing_key, hello)
                    .is_err()
                {
                    return;
                }
                match &entry.session {
                    PeerSession::Initiator {
                        hello: local_hello, ..
                    } => {
                        if peer_hello_wins(local_hello, self.identity.xid, hello, peer) {
                            HelloAction::StartResponder
                        } else {
                            HelloAction::Ignore
                        }
                    }
                    PeerSession::Responder {
                        hello: stored,
                        reply,
                        deadline,
                        ..
                    } => {
                        if stored.nonce == (&hello.nonce).into() {
                            HelloAction::ResendReply {
                                reply: reply.clone(),
                                deadline: *deadline,
                            }
                        } else {
                            HelloAction::StartResponder
                        }
                    }
                    PeerSession::Disconnected | PeerSession::Connected { .. } => {
                        HelloAction::StartResponder
                    }
                }
            }
            None => return,
        };
        let meta: ControlMeta = (&hello.meta).into();
        if self.is_replayed_control(peer, meta) {
            return;
        }

        match action {
            HelloAction::StartResponder => {
                self.start_responder_handshake(now, peer, hello, crypto, emit)
            }
            HelloAction::ResendReply { reply, deadline } => {
                let record = QlRecord {
                    header: QlHeader {
                        sender: self.identity.xid,
                        recipient: peer,
                    },
                    payload: QlPayload::Handshake(HandshakeRecord::HelloReply(reply)),
                };
                let token = self.state.next_token();
                self.enqueue_handshake_message(token, deadline, wire::encode_record(&record));
            }
            HelloAction::Ignore => {}
        }
    }

    fn handle_hello_reply(
        &mut self,
        now: Instant,
        peer: XID,
        reply: &wire::handshake::ArchivedHelloReply,
        emit: &mut impl OutputFn,
    ) {
        let deadline = now + self.config.handshake_timeout;
        let confirm_meta = self.next_control_meta(self.config.handshake_timeout);
        let res = {
            let Some(peer_record) = self.state.peer.as_ref() else {
                return;
            };
            let PeerSession::Initiator {
                hello,
                session_key,
                stage,
                ..
            } = &peer_record.session
            else {
                return;
            };
            if *stage != InitiatorStage::WaitingHelloReply {
                return;
            }
            handshake::build_confirm(
                &self.identity,
                peer,
                &peer_record.signing_key,
                hello,
                reply,
                session_key,
                confirm_meta,
            )
            .map(|(confirm, session_key)| (hello.clone(), confirm, session_key))
        };
        let (hello, confirm, session_key) = match res {
            Ok(result) => result,
            Err(_) => {
                if let Some(entry) = self.state.peer.as_mut() {
                    entry.session = PeerSession::Disconnected;
                }
                self.emit_peer_status(emit);
                return;
            }
        };
        let reply_meta: ControlMeta = (&reply.meta).into();
        if self.is_replayed_control(peer, reply_meta) {
            return;
        }
        let token = self.state.next_token();
        if let Some(entry) = self.state.peer.as_mut() {
            entry.session = PeerSession::Initiator {
                handshake_token: token,
                hello,
                session_key,
                deadline,
                stage: InitiatorStage::SendingConfirm,
            };
        }

        let record = QlRecord {
            header: QlHeader {
                sender: self.identity.xid,
                recipient: peer,
            },
            payload: QlPayload::Handshake(HandshakeRecord::Confirm(confirm)),
        };
        self.enqueue_handshake_message(token, deadline, wire::encode_record(&record));
    }

    fn handle_confirm(
        &mut self,
        now: Instant,
        peer: XID,
        confirm: &wire::handshake::ArchivedConfirm,
        emit: &mut impl OutputFn,
    ) {
        let Some(peer_record) = self.state.peer.as_ref() else {
            return;
        };
        let PeerSession::Responder {
            hello,
            reply,
            secrets,
            ..
        } = &peer_record.session
        else {
            return;
        };

        match handshake::finalize_confirm(
            peer,
            self.identity.xid,
            &peer_record.signing_key,
            hello,
            reply,
            confirm,
            secrets,
        ) {
            Ok(session_key) => {
                let meta: ControlMeta = (&confirm.meta).into();
                if self.is_replayed_control(peer, meta) {
                    return;
                }
                if let Some(entry) = self.state.peer.as_mut() {
                    entry.session = PeerSession::Connected {
                        session_key,
                        keepalive: KeepAliveState::default(),
                    };
                }
                self.record_activity(now);
                self.emit_peer_status(emit);
            }
            Err(_) => {
                if let Some(entry) = self.state.peer.as_mut() {
                    entry.session = PeerSession::Disconnected;
                }
                self.emit_peer_status(emit);
            }
        }
    }

    fn start_responder_handshake(
        &mut self,
        now: Instant,
        peer: XID,
        hello: &wire::handshake::ArchivedHello,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        let reply_meta = self.next_control_meta(self.config.handshake_timeout);
        let res = {
            let Some(peer_record) = self.state.peer.as_ref() else {
                return;
            };
            handshake::respond_hello(
                &self.identity,
                crypto,
                peer,
                &peer_record.signing_key,
                &peer_record.encapsulation_key,
                hello,
                reply_meta,
            )
        };
        let (reply, secrets) = match res {
            Ok(result) => result,
            Err(_) => {
                if let Some(entry) = self.state.peer.as_mut() {
                    entry.session = PeerSession::Disconnected;
                }
                self.emit_peer_status(emit);
                return;
            }
        };
        let Ok(hello) = wire::deserialize_value(hello) else {
            if let Some(entry) = self.state.peer.as_mut() {
                entry.session = PeerSession::Disconnected;
            }
            self.emit_peer_status(emit);
            return;
        };

        let deadline = now + self.config.handshake_timeout;
        let token = self.state.next_token();
        if let Some(entry) = self.state.peer.as_mut() {
            entry.session = PeerSession::Responder {
                handshake_token: token,
                hello,
                reply: reply.clone(),
                secrets,
                deadline,
            };
        }
        self.emit_peer_status(emit);

        let record = QlRecord {
            header: QlHeader {
                sender: self.identity.xid,
                recipient: peer,
            },
            payload: QlPayload::Handshake(HandshakeRecord::HelloReply(reply)),
        };
        self.enqueue_handshake_message(token, deadline, wire::encode_record(&record));
    }

    fn send_heartbeat_message(&mut self, now: Instant, crypto: &impl QlCrypto) {
        let Some(peer) = self.state.peer.as_ref().map(|peer| peer.peer) else {
            return;
        };
        let meta = self.next_control_meta(self.config.packet_expiration);
        let token = self.state.next_token();
        let deadline = now + self.config.packet_expiration;
        let message = {
            let Some(peer_record) = self.state.peer.as_ref() else {
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
        self.enqueue_handshake_message(token, deadline, wire::encode_record(&message));
    }

    fn keep_alive_config(&self) -> Option<KeepAliveConfig> {
        self.config
            .keep_alive
            .filter(|config| !config.interval.is_zero() && !config.timeout.is_zero())
    }

    fn record_activity(&mut self, now: Instant) {
        let Some(config) = self.keep_alive_config() else {
            return;
        };
        let token = self.state.next_token();
        let Some(entry) = self.state.peer.as_mut() else {
            return;
        };
        let PeerSession::Connected { keepalive, .. } = &mut entry.session else {
            return;
        };
        keepalive.last_activity = Some(now);
        keepalive.pending = false;
        keepalive.token = token;
        self.state.timeouts.push(Reverse(TimeoutEntry {
            at: now + config.interval,
            kind: TimeoutKind::KeepAliveSend { token },
        }));
    }

    fn record_stream_activity(&mut self, stream_id: StreamId, now: Instant) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            *stream.last_activity_mut() = now;
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
        match stream {
            StreamState::Initiator(stream) => {
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
            StreamState::Responder(stream) => {
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
            StreamState::Provisional(_) => {}
        }
        emit(EngineOutput::StreamReaped { stream_id });
    }

    fn unpair_peer(&mut self, emit: &mut impl OutputFn) {
        let Some(peer) = self.state.peer.as_ref().map(|peer| peer.peer) else {
            return;
        };
        self.drop_outbound();
        self.abort_streams(QlError::SendFailed, emit);
        self.state.peer = None;
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
                TimeoutKind::Handshake { token } => {
                    let Some(entry) = self.state.peer.as_ref() else {
                        continue;
                    };
                    let should_disconnect = matches!(
                        &entry.session,
                        PeerSession::Initiator { handshake_token, .. } | PeerSession::Responder { handshake_token, .. }
                            if *handshake_token == token
                    );
                    if should_disconnect {
                        if let Some(entry) = self.state.peer.as_mut() {
                            entry.session = PeerSession::Disconnected;
                        }
                        self.emit_peer_status(emit);
                        self.drop_outbound();
                        self.abort_streams(QlError::SendFailed, emit);
                    }
                }
                TimeoutKind::KeepAliveSend { token } => {
                    let Some(config) = self.keep_alive_config() else {
                        continue;
                    };
                    let should_send = {
                        let Some(entry) = self.state.peer.as_ref() else {
                            continue;
                        };
                        let PeerSession::Connected { keepalive, .. } = &entry.session else {
                            continue;
                        };
                        keepalive.token == token && !keepalive.pending
                    };
                    if should_send {
                        self.send_heartbeat_message(now, crypto);
                    }
                    if let Some(entry) = self.state.peer.as_mut() {
                        if let PeerSession::Connected { keepalive, .. } = &mut entry.session {
                            if keepalive.token == token {
                                keepalive.pending = true;
                            }
                        }
                    }
                    self.state.timeouts.push(Reverse(TimeoutEntry {
                        at: now + config.timeout,
                        kind: TimeoutKind::KeepAliveTimeout { token },
                    }));
                }
                TimeoutKind::KeepAliveTimeout { token } => {
                    let Some(entry) = self.state.peer.as_ref() else {
                        continue;
                    };
                    let should_disconnect = matches!(&entry.session, PeerSession::Connected { keepalive, .. } if keepalive.token == token && keepalive.pending);
                    if should_disconnect {
                        if let Some(entry) = self.state.peer.as_mut() {
                            entry.session = PeerSession::Disconnected;
                        }
                        self.emit_peer_status(emit);
                        self.drop_outbound();
                        self.abort_streams(QlError::SendFailed, emit);
                    }
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
                        let control = stream.control_mut();
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
    }
}

fn encrypted_message_nonce(crypto: &impl QlCrypto) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    crypto.fill_random_bytes(&mut nonce);
    nonce
}

fn peer_hello_wins(
    local_hello: &Hello,
    local_sender: XID,
    peer_hello: &wire::handshake::ArchivedHello,
    peer_sender: XID,
) -> bool {
    use std::cmp::Ordering;

    let peer_nonce: bc_components::Nonce = (&peer_hello.nonce).into();
    match peer_nonce.data().cmp(local_hello.nonce.data()) {
        Ordering::Less => true,
        Ordering::Greater => false,
        Ordering::Equal => peer_sender.data().cmp(local_sender.data()) == Ordering::Less,
    }
}

fn reset_target_for_dir(dir: Direction) -> ResetTarget {
    match dir {
        Direction::Request => ResetTarget::Request,
        Direction::Response => ResetTarget::Response,
    }
}
