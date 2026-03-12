pub mod replay_cache;
mod state;
mod stream;

#[cfg(test)]
mod tests;

use std::{
    cmp::Reverse,
    collections::HashMap,
    mem,
    time::{Duration, Instant},
};

use bc_components::{SigningPublicKey, XID};
use rkyv::access_mut;
pub use state::{
    Engine, EngineInput, EngineOutput, EngineState, InitiatorStage, KeepAliveState, OpenId,
    OutputFn, PeerRecord, PeerSession, Token, TrackedWrite,
};

use self::{
    replay_cache::{ReplayKey, ReplayNamespace},
    state::*,
    stream::*,
};
use crate::{
    platform::QlCrypto,
    wire::{
        self,
        encrypted_message::{ArchivedEncryptedMessage, NONCE_SIZE},
        handshake::{self, HandshakeRecord, Hello},
        heartbeat::{self, HeartbeatBody},
        stream::{
            decrypt_stream, encrypt_stream, BodyChunk, Direction, RejectCode, ResetCode,
            ResetTarget, StreamFrame, StreamFrameAccept, StreamFrameData, StreamFrameOpen,
            StreamFrameReject, StreamFrameReset, StreamMessage,
        },
        unpair::{self},
        QlHeader, QlPayload, QlRecord,
    },
    PacketId, Peer, QlError, StreamId, StreamSeq,
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
    pub stream_ack_timeout: Duration,
    pub stream_retry_limit: u8,
    pub max_payload_bytes: usize,
    pub keep_alive: Option<KeepAliveConfig>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
            default_open_timeout: Duration::from_secs(5),
            packet_expiration: Duration::from_secs(30),
            stream_ack_timeout: Duration::from_millis(150),
            stream_retry_limit: 5,
            max_payload_bytes: 1024,
            keep_alive: None,
        }
    }
}

impl EngineConfig {
    pub(crate) fn normalized(mut self) -> Self {
        self.max_payload_bytes = self.max_payload_bytes.max(1);
        self
    }
}

impl Engine {
    pub fn new(config: EngineConfig, local_xid: XID, peer: Option<Peer>) -> Self {
        Self {
            config: config.normalized(),
            local_xid,
            state: EngineState::new(peer),
            streams: HashMap::new(),
        }
    }

    pub fn run_tick(
        &mut self,
        now: Instant,
        input: EngineInput,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        debug_assert_eq!(self.local_xid, crypto.xid());

        match input {
            EngineInput::BindPeer(peer) => self.handle_bind_peer(peer, emit),
            EngineInput::Pair => self.handle_pair_local(now, crypto),
            EngineInput::Connect => self.handle_connect(now, crypto, emit),
            EngineInput::Unpair => self.handle_unpair_local(now, crypto, emit),
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
                offset,
                bytes,
            } => self.handle_outbound_data(stream_id, dir, offset, bytes),
            EngineInput::OutboundFinished {
                stream_id,
                dir,
                final_offset,
            } => self.handle_outbound_finished(stream_id, dir, final_offset),
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
            EngineInput::WriteCompleted {
                token,
                tracked,
                result,
            } => self.handle_write_done(now, token, tracked, result, emit),
            EngineInput::TimerExpired => self.handle_timeouts(now, crypto, emit),
        }

        self.drive_streams(now, emit);
        self.maybe_start_next_write(crypto, emit);
        emit(EngineOutput::SetTimer(self.state.next_deadline()));
    }

    fn emit_peer_status(&self, emit: &mut impl OutputFn) {
        if let Some(peer) = self.state.peer.as_ref() {
            emit(EngineOutput::PeerStatusChanged {
                peer: peer.peer,
                session: peer.session.clone(),
            });
        }
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
        let streams = mem::take(&mut self.streams);
        for (stream_id, stream) in streams {
            self.fail_stream(stream_id, stream, error.clone(), emit);
        }
        self.state.outbound.clear();
        self.state.timeouts.clear();
        self.state.write_in_flight = None;
        if let Some(peer) = self.state.peer.as_ref().map(|peer| peer.peer) {
            self.state.replay_cache.clear_peer(peer);
        }
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
        let Ok(record) = wire::pair::build_pair_request(
            crypto,
            peer.peer,
            &peer.encapsulation_key,
            self.state.next_packet_id(),
            self.config.packet_expiration,
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
        let (hello, session_key) = match &peer_record.session {
            PeerSession::Connected { .. }
            | PeerSession::Initiator { .. }
            | PeerSession::Responder { .. } => {
                return;
            }
            PeerSession::Disconnected => {
                match handshake::build_hello(
                    crypto,
                    crypto.xid(),
                    peer,
                    &peer_record.encapsulation_key,
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
                sender: crypto.xid(),
                recipient: peer,
            },
            payload: QlPayload::Handshake(HandshakeRecord::Hello(hello)),
        };
        self.enqueue_handshake_message(token, deadline, wire::encode_record(&record));
    }

    fn handle_unpair_local(
        &mut self,
        now: Instant,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        let Some(peer) = self.state.peer.as_ref().map(|peer| peer.peer) else {
            return;
        };
        let record = unpair::build_unpair_record(
            crypto,
            QlHeader {
                sender: crypto.xid(),
                recipient: peer,
            },
            self.state.next_packet_id(),
            wire::now_secs().saturating_add(self.config.packet_expiration.as_secs()),
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

        let stream_namespace = StreamNamespace::for_local(self.local_xid, entry.peer);
        let stream_id = self.state.next_stream_id(stream_namespace);
        let open_timeout = config
            .open_timeout
            .unwrap_or(self.config.default_open_timeout);
        let token = self.state.next_token();
        let request_prefix_end = request_prefix
            .as_ref()
            .map(|chunk| chunk.offset.saturating_add(chunk.bytes.len() as u64))
            .unwrap_or(0);
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
                pending: PendingFrames {
                    setup: Some(StreamFrame::Open(frame)),
                    ..Default::default()
                },
                ..Default::default()
            },
            request: OutboundState {
                dir: Direction::Request,
                sent_offset: request_prefix_end,
                final_offset: request_prefix_fin.then_some(request_prefix_end),
                closed: false,
                pending_pull: None,
            },
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
        let response_prefix_end = response_prefix
            .as_ref()
            .map(|chunk| chunk.offset.saturating_add(chunk.bytes.len() as u64))
            .unwrap_or(0);
        let response_prefix_fin = response_prefix.as_ref().is_some_and(|chunk| chunk.fin);
        stream
            .control
            .pending
            .set_setup(StreamFrame::Accept(StreamFrameAccept {
                stream_id,
                response_head,
                response_prefix,
            }));
        stream.response = ResponderResponse::Accepted {
            body: OutboundState {
                dir: Direction::Response,
                sent_offset: response_prefix_end,
                final_offset: response_prefix_fin.then_some(response_prefix_end),
                closed: false,
                pending_pull: None,
            },
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
            .set_setup(StreamFrame::Reject(StreamFrameReject { stream_id, code }));
        stream.response = ResponderResponse::Rejecting;
        stream.meta.last_activity = now;
    }

    fn handle_outbound_data(
        &mut self,
        stream_id: StreamId,
        dir: Direction,
        offset: u64,
        bytes: Vec<u8>,
    ) {
        if bytes.is_empty() {
            return;
        }
        let (streams, state) = (&mut self.streams, &mut self.state);
        let Some(stream) = streams.get_mut(&stream_id) else {
            return;
        };
        let Some(outbound) = stream.outbound_mut(dir) else {
            return;
        };
        let Some(pull) = outbound.pending_pull.take() else {
            return;
        };
        if pull.offset != offset {
            outbound.pending_pull = Some(pull);
            return;
        }
        if bytes.len() > pull.max_len {
            outbound.pending_pull = Some(pull);
            return;
        }
        let end = offset.saturating_add(bytes.len() as u64);
        let final_offset = outbound.final_offset;
        if let Some(final_offset) = final_offset {
            if end > final_offset {
                outbound.pending_pull = Some(pull);
                return;
            }
        }
        outbound.sent_offset = outbound.sent_offset.max(end);
        let fin = final_offset.is_some_and(|final_offset| final_offset == end);
        let chunk = BodyChunk { offset, fin, bytes };
        let _ = outbound;
        let stream_id = stream.stream_id();
        let control = stream.control_mut();
        state.enqueue_data_frame(&self.config, stream_id, control, dir, chunk, 0);
    }

    fn handle_outbound_finished(&mut self, stream_id: StreamId, dir: Direction, final_offset: u64) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let Some(outbound) = stream.outbound_mut(dir) else {
            return;
        };
        if final_offset < outbound.sent_offset {
            return;
        }
        outbound.pending_pull = None;
        outbound.final_offset = Some(final_offset);
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
        if outbound.closed {
            return;
        }
        outbound.closed = true;
        outbound.pending_pull = None;
        stream
            .control_mut()
            .pending
            .set_reset(reset_target_for_dir(dir), code);
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
        stream
            .control_mut()
            .pending
            .set_reset(reset_target_for_dir(dir), code);
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
        let sender = wire::xid_from_archived(&record.header.sender);
        let recipient = wire::xid_from_archived(&record.header.recipient);
        if recipient != crypto.xid() {
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
                self.handle_hello_reply(now, peer, reply, crypto, emit)
            }
            wire::handshake::ArchivedHandshakeRecord::Confirm(confirm) => {
                self.handle_confirm(now, peer, confirm, crypto, emit)
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
        let payload = match wire::pair::decrypt_pair_request(crypto, header, request) {
            Ok(payload) => payload,
            Err(_) => return,
        };
        let peer = XID::new(SigningPublicKey::MLDSA(payload.signing_pub_key.clone()));
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
        let packet_id: PacketId = (&record.packet_id).into();
        let valid_until = record.valid_until.to_native();
        let replay_key = ReplayKey::new(peer, ReplayNamespace::Peer, packet_id);
        if self
            .state
            .replay_cache
            .check_and_store_valid_until(replay_key, valid_until)
        {
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
        let should_reply = {
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
            if heartbeat::decrypt_heartbeat(header, encrypted, session_key).is_err() {
                return;
            }
            !keepalive.pending
        };
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
        let message = {
            let Some(peer_record) = self.state.peer.as_ref() else {
                return;
            };
            let PeerSession::Connected { session_key, .. } = &peer_record.session else {
                return;
            };
            match decrypt_stream(header, encrypted, session_key) {
                Ok(message) => message,
                Err(_) => return,
            }
        };

        let stream_id = message.frame.stream_id();
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            if !matches!(message.frame, StreamFrame::Open(_)) || message.tx_seq != StreamSeq(1) {
                return;
            }
            // if we have a disagreement over stream namespace, close stream
            if self.state.peer.as_ref().is_some_and(|peer_record| {
                let local_namespace = StreamNamespace::for_local(self.local_xid, peer_record.peer);
                !local_namespace.remote().matches(stream_id)
            }) {
                self.send_ephemeral_reset(stream_id, ResetTarget::Both, ResetCode::Protocol);
                return;
            }
            self.record_activity(now);
            self.record_stream_activity(stream_id, now);
            match message.frame {
                StreamFrame::Open(frame) => {
                    self.handle_stream_open(now, frame, emit);
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        stream.control_mut().next_rx_seq = StreamSeq(2);
                        stream.control_mut().mark_ack(StreamSeq(1));
                    }
                }
                _ => unreachable!(),
            }
            return;
        };

        let expected = stream.control().next_rx_seq;
        if message.tx_seq.0 < expected.0 {
            if !matches!(message.frame, StreamFrame::Ack(_)) {
                stream
                    .control_mut()
                    .mark_ack(StreamSeq(expected.0.saturating_sub(1)));
            }
            if let Some(ack_seq) = message.ack_seq {
                self.process_stream_ack(stream_id, ack_seq, emit);
            }
            return;
        } else if message.tx_seq != expected {
            // can never happen with stop & wait windowing
            Self::queue_protocol_reset(stream, emit);
            *stream.last_activity_mut() = now;
            return;
        }

        stream.control_mut().next_rx_seq = StreamSeq(expected.0.wrapping_add(1));
        if !matches!(message.frame, StreamFrame::Ack(_)) {
            stream.control_mut().mark_ack(message.tx_seq);
        }

        if let Some(ack_seq) = message.ack_seq {
            self.process_stream_ack(stream_id, ack_seq, emit);
        }

        self.record_activity(now);
        self.record_stream_activity(stream_id, now);

        match message.frame {
            StreamFrame::Open(frame) => self.handle_stream_open(now, frame, emit),
            StreamFrame::Accept(frame) => self.handle_stream_accept_from_peer(now, frame, emit),
            StreamFrame::Reject(frame) => self.handle_stream_reject_from_peer(frame, emit),
            StreamFrame::Data(frame) => self.handle_stream_data(now, frame, emit),
            StreamFrame::Reset(frame) => self.handle_stream_reset(now, frame, emit),
            StreamFrame::Ack(_) => {}
        }
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
        if let Some(stream) = self.streams.get(&stream_id) {
            let _ = stream;
            self.send_ephemeral_reset(stream_id, ResetTarget::Both, ResetCode::Protocol);
            return;
        }

        let mut stream = StreamState::Responder(ResponderStream {
            meta: StreamMeta {
                stream_id,
                last_activity: now,
            },
            control: StreamControl::default(),
            request: InboundState::new(),
            response: ResponderResponse::Pending,
        });
        if let Some(chunk) = request_prefix.as_ref() {
            let Some(inbound) = stream.inbound_mut(Direction::Request) else {
                return;
            };
            let end = chunk.offset.saturating_add(chunk.bytes.len() as u64);
            if chunk.offset != 0 {
                self.send_ephemeral_reset(stream_id, ResetTarget::Both, ResetCode::Protocol);
                return;
            }
            inbound.next_offset = end;
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
                            stream
                                .control
                                .pending
                                .set_reset(ResetTarget::Response, ResetCode::Cancelled);
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
                            stream
                                .control
                                .pending
                                .set_reset(ResetTarget::Response, ResetCode::Cancelled);
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
            let end = chunk.offset.saturating_add(chunk.bytes.len() as u64);
            if chunk.offset != inbound.next_offset {
                Self::queue_protocol_reset(stream, emit);
                return;
            }
            inbound.next_offset = end;
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
                        stream.request.closed = true;
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
            let end = chunk.offset.saturating_add(chunk.bytes.len() as u64);
            if chunk.offset != inbound.next_offset {
                Self::queue_protocol_reset(stream, emit);
            } else {
                inbound.next_offset = end;
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
        stream_id: StreamId,
        ack_seq: StreamSeq,
        emit: &mut impl OutputFn,
    ) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let should_clear = stream
            .control()
            .awaiting
            .as_ref()
            .is_some_and(|awaiting| awaiting.tx_seq.0 <= ack_seq.0);
        if !should_clear {
            return;
        }
        let Some(awaiting) = stream.control_mut().awaiting.take() else {
            return;
        };

        match awaiting.frame {
            StreamFrame::Open(StreamFrameOpen { request_prefix, .. }) => {
                if let StreamState::Initiator(stream) = stream {
                    if let InitiatorAccept::Opening(waiter) = &stream.accept {
                        stream.accept = InitiatorAccept::WaitingAccept(OpenWaiter {
                            open_id: waiter.open_id,
                            open_timeout_token: waiter.open_timeout_token,
                        });
                    }
                    if request_prefix.as_ref().is_some_and(|chunk| chunk.fin) {
                        stream.request.closed = true;
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
                            body.closed = true;
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
                    outbound.closed = true;
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
                            outbound.closed = true;
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
            StreamFrame::Ack(_) => {}
        }

        self.maybe_reap_stream(stream_id, emit);
    }

    fn drive_streams(&mut self, now: Instant, emit: &mut impl OutputFn) {
        let config = &self.config;
        let state = &mut self.state;
        for stream in self.streams.values_mut() {
            Self::drive_stream(config, state, now, stream, emit);
        }
    }

    fn drive_stream(
        config: &EngineConfig,
        state: &mut EngineState,
        _now: Instant,
        stream: &mut StreamState,
        emit: &mut impl OutputFn,
    ) {
        match stream {
            StreamState::Initiator(stream) => {
                let action = Self::plan_drive_outbound(
                    config,
                    stream.meta.stream_id,
                    &mut stream.control,
                    Some(&mut stream.request),
                    emit,
                );
                if let Some(frame) = action {
                    state.enqueue_stream_frame(
                        config,
                        stream.meta.stream_id,
                        &mut stream.control,
                        frame,
                        0,
                    );
                }
            }
            StreamState::Responder(stream) => {
                let stream_id = stream.meta.stream_id;
                match &mut stream.response {
                    ResponderResponse::Accepted { body, .. } => {
                        let action = Self::plan_drive_outbound(
                            config,
                            stream_id,
                            &mut stream.control,
                            Some(body),
                            emit,
                        );
                        if let Some(frame) = action {
                            state.enqueue_stream_frame(
                                config,
                                stream_id,
                                &mut stream.control,
                                frame,
                                0,
                            );
                        }
                    }
                    _ => {
                        let action = Self::plan_drive_outbound(
                            config,
                            stream_id,
                            &mut stream.control,
                            None,
                            emit,
                        );
                        if let Some(frame) = action {
                            state.enqueue_stream_frame(
                                config,
                                stream_id,
                                &mut stream.control,
                                frame,
                                0,
                            );
                        }
                    }
                }
            }
        }
    }

    fn plan_drive_outbound(
        config: &EngineConfig,
        stream_id: StreamId,
        control: &mut StreamControl,
        outbound: Option<&mut OutboundState>,
        emit: &mut impl OutputFn,
    ) -> Option<StreamFrame> {
        if control.awaiting.is_some() {
            return None;
        }
        if let Some(frame) = control.pending.take_next_control(stream_id) {
            return Some(frame);
        }
        if control.pending_ack_seq.is_some() {
            return Some(StreamFrame::Ack(crate::wire::stream::StreamFrameAck {
                stream_id,
            }));
        }
        let outbound = outbound?;
        if outbound.can_request_data() {
            let max_len = config.max_payload_bytes;
            if max_len > 0 {
                outbound.pending_pull = Some(PendingPull {
                    offset: outbound.sent_offset,
                    max_len,
                });
                emit(EngineOutput::NeedOutboundData {
                    stream_id,
                    dir: outbound.dir,
                    offset: outbound.sent_offset,
                    max_len,
                });
            }
            return None;
        }
        if !outbound.closed
            && outbound.pending_pull.is_none()
            && outbound
                .final_offset
                .is_some_and(|final_offset| final_offset == outbound.sent_offset)
        {
            return Some(StreamFrame::Data(StreamFrameData {
                stream_id,
                dir: outbound.dir,
                chunk: BodyChunk {
                    offset: outbound.sent_offset,
                    bytes: Vec::new(),
                    fin: true,
                },
            }));
        }
        None
    }

    fn queue_protocol_reset(stream: &mut StreamState, emit: &mut impl OutputFn) {
        let stream_id = stream.stream_id();
        stream
            .control_mut()
            .pending
            .set_reset(ResetTarget::Both, ResetCode::Protocol);
        for dir in [Direction::Request, Direction::Response] {
            if let Some(outbound) = stream.outbound_mut(dir) {
                outbound.closed = true;
                outbound.pending_pull = None;
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
                outbound.closed = true;
                outbound.pending_pull = None;
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
                outbound.closed = true;
                outbound.pending_pull = None;
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

    fn send_ephemeral_reset(&mut self, stream_id: StreamId, dir: ResetTarget, code: ResetCode) {
        let valid_until = wire::now_secs().saturating_add(self.config.packet_expiration.as_secs());
        self.enqueue_stream_message(
            None,
            None,
            false,
            true,
            StreamMessage {
                tx_seq: StreamSeq(1),
                ack_seq: None,
                valid_until,
                frame: StreamFrame::Reset(StreamFrameReset {
                    stream_id,
                    target: dir,
                    code,
                }),
            },
        );
    }

    fn enqueue_handshake_message(&mut self, token: Token, deadline: Instant, bytes: Vec<u8>) {
        self.state
            .enqueue_handshake_message(&self.config, token, deadline, bytes);
    }

    fn enqueue_stream_message(
        &mut self,
        stream_id: Option<StreamId>,
        tx_seq: Option<StreamSeq>,
        track_ack: bool,
        priority: bool,
        message: StreamMessage,
    ) {
        self.state.enqueue_stream_message(
            &self.config,
            stream_id,
            tx_seq,
            track_ack,
            priority,
            message,
        );
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
            Some(entry) => match &entry.session {
                PeerSession::Initiator {
                    hello: local_hello, ..
                } => {
                    if peer_hello_wins(local_hello, crypto.xid(), hello, peer) {
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
                    if stored.nonce == wire::nonce_from_archived(&hello.nonce) {
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
            },
            None => return,
        };

        match action {
            HelloAction::StartResponder => {
                self.start_responder_handshake(now, peer, hello, crypto, emit)
            }
            HelloAction::ResendReply { reply, deadline } => {
                let record = QlRecord {
                    header: QlHeader {
                        sender: crypto.xid(),
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
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        let token = self.state.next_token();
        let deadline = now + self.config.handshake_timeout;
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
                crypto,
                crypto.xid(),
                peer,
                &peer_record.signing_key,
                hello,
                reply,
                session_key,
            )
            .map(|(confirm, session_key)| (hello.clone(), confirm, session_key))
        };
        let confirm = match res {
            Ok((hello, confirm, session_key)) => {
                if let Some(entry) = self.state.peer.as_mut() {
                    entry.session = PeerSession::Initiator {
                        handshake_token: token,
                        hello,
                        session_key,
                        deadline,
                        stage: InitiatorStage::SendingConfirm,
                    };
                }
                confirm
            }
            Err(_) => {
                if let Some(entry) = self.state.peer.as_mut() {
                    entry.session = PeerSession::Disconnected;
                }
                self.emit_peer_status(emit);
                return;
            }
        };

        let record = QlRecord {
            header: QlHeader {
                sender: crypto.xid(),
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
        crypto: &impl QlCrypto,
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
            crypto.xid(),
            &peer_record.signing_key,
            hello,
            reply,
            confirm,
            secrets,
        ) {
            Ok(session_key) => {
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
        let res = {
            let Some(peer_record) = self.state.peer.as_ref() else {
                return;
            };
            handshake::respond_hello(
                crypto,
                peer,
                crypto.xid(),
                &peer_record.encapsulation_key,
                hello,
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
                sender: crypto.xid(),
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
        let packet_id = self.state.next_packet_id();
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
                    sender: crypto.xid(),
                    recipient: peer,
                },
                session_key,
                HeartbeatBody {
                    packet_id,
                    valid_until: wire::now_secs()
                        .saturating_add(self.config.packet_expiration.as_secs()),
                },
                next_encrypted_message_nonce(crypto),
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

    fn drop_outbound(&mut self, emit: &mut impl OutputFn) {
        while let Some(message) = self.state.outbound.pop_front() {
            if let Some(stream_id) = message.stream_id {
                self.fail_stream_by_id(stream_id, QlError::SendFailed, emit);
            }
        }
    }

    fn abort_streams(&mut self, error: QlError, emit: &mut impl OutputFn) {
        let streams = mem::take(&mut self.streams);
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
        }
        emit(EngineOutput::StreamReaped { stream_id });
    }

    fn unpair_peer(&mut self, emit: &mut impl OutputFn) {
        let Some(peer) = self.state.peer.as_ref().map(|peer| peer.peer) else {
            return;
        };
        self.drop_outbound(emit);
        self.abort_streams(QlError::SendFailed, emit);
        self.state.replay_cache.clear_peer(peer);
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
                    let mut timed_out_stream = None;
                    self.state.outbound.retain(|message| {
                        if message.token == token {
                            timed_out_stream = message.stream_id;
                            false
                        } else {
                            true
                        }
                    });
                    if let Some(stream_id) = timed_out_stream {
                        self.fail_stream_by_id(stream_id, QlError::SendFailed, emit);
                    }
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
                        self.drop_outbound(emit);
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
                        self.drop_outbound(emit);
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
                TimeoutKind::StreamMessage {
                    stream_id,
                    tx_seq,
                    attempt,
                } => {
                    let Some(frame) = self.streams.get(&stream_id).and_then(|stream| {
                        stream.control().awaiting.as_ref().and_then(|awaiting| {
                            (awaiting.tx_seq == tx_seq && awaiting.attempt == attempt)
                                .then_some(awaiting.frame.clone())
                        })
                    }) else {
                        continue;
                    };

                    if attempt >= self.config.stream_retry_limit {
                        self.fail_stream_by_id(stream_id, QlError::Timeout, emit);
                    } else {
                        let (streams, state) = (&mut self.streams, &mut self.state);
                        if let Some(stream) = streams.get_mut(&stream_id) {
                            state.enqueue_stream_frame(
                                &self.config,
                                stream.stream_id(),
                                stream.control_mut(),
                                frame,
                                attempt.saturating_add(1),
                            );
                        }
                    }
                }
            }
        }
    }

    fn handle_write_done(
        &mut self,
        now: Instant,
        token: Token,
        tracked: Option<TrackedWrite>,
        result: Result<(), QlError>,
        emit: &mut impl OutputFn,
    ) {
        if self.state.write_in_flight == Some(token) {
            self.state.write_in_flight = None;
        }
        if let Err(error) = result {
            if let Some(tracked) = tracked {
                self.fail_stream_by_id(tracked.stream_id, error.clone(), emit);
            }
            let should_disconnect = matches!(self.state.peer.as_ref().map(|entry| &entry.session),
                Some(PeerSession::Initiator { handshake_token, .. }) if *handshake_token == token)
                || matches!(self.state.peer.as_ref().map(|entry| &entry.session),
                Some(PeerSession::Responder { handshake_token, .. }) if *handshake_token == token);
            if should_disconnect {
                if let Some(entry) = self.state.peer.as_mut() {
                    entry.session = PeerSession::Disconnected;
                }
                self.emit_peer_status(emit);
                self.drop_outbound(emit);
                self.abort_streams(error, emit);
            }
            return;
        }

        let connected = self
            .state
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
            });
        if let Some(session_key) = connected {
            if let Some(entry) = self.state.peer.as_mut() {
                entry.session = PeerSession::Connected {
                    session_key,
                    keepalive: KeepAliveState::default(),
                };
            }
            self.emit_peer_status(emit);
            self.record_activity(now);
        }

        if let Some(tracked) = tracked {
            let attempt = self
                .streams
                .get(&tracked.stream_id)
                .and_then(|stream| stream.control().awaiting.as_ref())
                .and_then(|awaiting| {
                    (awaiting.tx_seq == tracked.tx_seq).then_some(awaiting.attempt)
                })
                .unwrap_or(0);
            self.state.timeouts.push(Reverse(TimeoutEntry {
                at: now + self.config.stream_ack_timeout,
                kind: TimeoutKind::StreamMessage {
                    stream_id: tracked.stream_id,
                    tx_seq: tracked.tx_seq,
                    attempt,
                },
            }));
        }
    }

    fn maybe_start_next_write(&mut self, crypto: &impl QlCrypto, emit: &mut impl OutputFn) {
        if self.state.write_in_flight.is_some() {
            return;
        }
        while let Some(message) = self.state.outbound.pop_front() {
            let bytes = match message.payload {
                QueuedPayload::PreEncoded(bytes) => bytes,
                QueuedPayload::StreamMessage(stream_message) => {
                    let Some(peer) = self.state.peer.as_ref() else {
                        if let Some(stream_id) = message.stream_id {
                            self.fail_stream_by_id(stream_id, QlError::SendFailed, emit);
                        }
                        continue;
                    };
                    let Some(session_key) = peer.session.session_key() else {
                        if let Some(stream_id) = message.stream_id {
                            self.fail_stream_by_id(stream_id, QlError::SendFailed, emit);
                        }
                        continue;
                    };
                    let record = encrypt_stream(
                        QlHeader {
                            sender: crypto.xid(),
                            recipient: peer.peer,
                        },
                        session_key,
                        stream_message,
                        next_encrypted_message_nonce(crypto),
                    );
                    wire::encode_record(&record)
                }
            };

            let tracked = if message.track_ack {
                message
                    .stream_id
                    .zip(message.tx_seq)
                    .map(|(stream_id, tx_seq)| TrackedWrite { stream_id, tx_seq })
            } else {
                None
            };
            self.state.write_in_flight = Some(message.token);
            emit(EngineOutput::WriteMessage {
                token: message.token,
                tracked,
                bytes,
            });
            break;
        }
    }
}

fn next_encrypted_message_nonce(crypto: &impl QlCrypto) -> [u8; NONCE_SIZE] {
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

    let peer_nonce = wire::nonce_from_archived(&peer_hello.nonce);
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
