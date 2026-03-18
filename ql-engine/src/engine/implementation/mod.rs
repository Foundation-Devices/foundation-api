pub mod handshake;
pub mod peer;
pub mod stream;

use std::time::{Duration, Instant};

use bc_components::{SigningPublicKey, SymmetricKey, XID};
use rkyv::access_mut;

use crate::{
    engine::{
        replay_cache::ReplayKey,
        state::{ActiveWrite, OutboundWriteKind, TimeoutKind},
        Engine, EngineEvent, HandshakeInitiator, HandshakeResponder, KeepAliveConfig,
        KeepAliveState, OutboundWrite, PeerRecord, PeerSession, QlCrypto, RecentReady,
        StreamConfig, Token, WriteId,
    },
    wire::{
        self,
        encrypted_message::{ArchivedEncryptedMessage, NONCE_SIZE},
        stream::{BodyChunk, CloseCode, CloseTarget},
        ControlMeta, QlHeader,
    },
    Peer, QlError, StreamId,
};

impl Engine {
    pub(crate) fn open_stream_inner(
        &mut self,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
        config: StreamConfig,
    ) -> Result<StreamId, QlError> {
        stream::open_stream(self, request_head, request_prefix, config)
    }

    pub(crate) fn bind_peer_inner(&mut self, peer: Peer) {
        peer::handle_bind_peer(self, peer);
    }

    pub(crate) fn pair_inner(&mut self, crypto: &impl QlCrypto) {
        peer::handle_pair_local(self, crypto);
    }

    pub(crate) fn connect_inner(&mut self, crypto: &impl QlCrypto) {
        handshake::handle_connect(self, crypto);
    }

    pub(crate) fn unpair_inner(&mut self) {
        peer::handle_unpair_local(self);
    }

    pub(crate) fn write_stream_inner(
        &mut self,
        stream_id: StreamId,
        bytes: Vec<u8>,
    ) -> Result<(), QlError> {
        stream::handle_outbound_data(self, stream_id, bytes)
    }

    pub(crate) fn finish_stream_inner(&mut self, stream_id: StreamId) -> Result<(), QlError> {
        stream::handle_outbound_finished(self, stream_id)
    }

    pub(crate) fn close_stream_inner(
        &mut self,
        stream_id: StreamId,
        target: CloseTarget,
        code: CloseCode,
        payload: Vec<u8>,
    ) -> Result<(), QlError> {
        stream::handle_close_stream(self, stream_id, target, code, payload)
    }

    pub(crate) fn receive_inner(&mut self, bytes: Vec<u8>, crypto: &impl QlCrypto) {
        self.handle_incoming(bytes, crypto);
    }

    pub(crate) fn take_next_write_inner(
        &mut self,
        crypto: &impl QlCrypto,
    ) -> Option<OutboundWrite> {
        self.take_next_control_write()
            .or_else(|| stream::take_next_stream_write(self, crypto))
    }

    pub(crate) fn complete_write_inner(&mut self, write_id: WriteId, result: Result<(), QlError>) {
        let Some(active) = self.state.active_writes.remove(write_id.0) else {
            return;
        };

        if let Err(error) = result {
            if let OutboundWriteKind::Stream(completion) = active.kind {
                stream::complete_stream_write(self, completion, Err(error.clone()));
            }

            if self.is_handshake_token(active.token) {
                if let Some(entry) = self.peer.as_mut() {
                    entry.session = PeerSession::Disconnected;
                }
                self.emit_peer_status();
                self.drop_outbound();
                self.abort_streams(error);
            }

            return;
        }

        if let Some((session_key, recent_ready)) = self.connected_session_for_token(active.token) {
            if let Some(entry) = self.peer.as_mut() {
                entry.session = PeerSession::Connected {
                    session_key,
                    keepalive: KeepAliveState::default(),
                    recent_ready,
                };
            }
            self.emit_peer_status();
            self.record_activity();
        }

        if let Some(token) = active.token {
            self.schedule_handshake_retry_after_write(token);
        }

        if let OutboundWriteKind::Stream(completion) = active.kind {
            stream::complete_stream_write(self, completion, Ok(()));
        }
    }

    pub(crate) fn on_timer_inner(&mut self, crypto: &impl QlCrypto) {
        let now = self.state.now;
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
            }
        }

        stream::handle_stream_timeouts(self);

        if let Some(PeerRecord {
            session: PeerSession::Connected { recent_ready, .. },
            ..
        }) = self.peer.as_mut()
        {
            if recent_ready
                .as_ref()
                .is_some_and(|ready| ready.expires_at <= now)
            {
                *recent_ready = None;
            }
        }

        let handshake_due = self
            .handshake_deadline()
            .is_some_and(|deadline| deadline <= now);
        if handshake_due {
            self.fail_handshake(QlError::Timeout);
            return;
        }

        let handshake_retry_due = self
            .handshake_retry_deadline()
            .is_some_and(|deadline| deadline <= now);
        if handshake_retry_due {
            self.handle_handshake_retry_timeout();
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
            self.emit_peer_status();
            self.drop_outbound();
            self.abort_streams(QlError::SendFailed);
            return;
        }

        self.send_heartbeat_message(crypto);
        if let Some(entry) = self.peer.as_mut() {
            if let PeerSession::Connected { keepalive, .. } = &mut entry.session {
                keepalive.pending = true;
                keepalive.last_activity = Some(now);
            }
        }
    }

    pub(crate) fn next_deadline_inner(&self) -> Option<Instant> {
        [
            self.state.next_deadline(),
            self.streams.next_deadline(),
            self.handshake_retry_deadline(),
            self.handshake_deadline(),
            self.keep_alive_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    pub(crate) fn abort_inner(&mut self, error: QlError) {
        self.abort_streams(error);
    }
}

impl Engine {
    fn emit_peer_status(&mut self) {
        let event = self
            .peer
            .as_ref()
            .map(|peer| EngineEvent::PeerStatusChanged {
                peer: peer.peer,
                session: peer.session.clone(),
            });
        if let Some(event) = event {
            self.state.pending_events.push_back(event);
        }
    }

    fn handle_incoming(&mut self, mut bytes: Vec<u8>, crypto: &impl QlCrypto) {
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
                self.handle_handshake(sender, &header, message, crypto)
            }
            wire::ArchivedQlPayload::Stream(encrypted) => {
                stream::handle_stream(self, sender, &header, encrypted)
            }
            wire::ArchivedQlPayload::Heartbeat(encrypted) => {
                self.handle_heartbeat(&header, encrypted, crypto)
            }
            wire::ArchivedQlPayload::Pair(request) => {
                peer::handle_pairing(self, &header, request, crypto)
            }
            wire::ArchivedQlPayload::Unpair(unpair_record) => {
                peer::handle_unpair(self, sender, &header, unpair_record)
            }
        }
    }

    fn handle_handshake(
        &mut self,
        peer: XID,
        header: &QlHeader,
        message: &mut wire::handshake::ArchivedHandshakeRecord,
        crypto: &impl QlCrypto,
    ) {
        match message {
            wire::handshake::ArchivedHandshakeRecord::Hello(hello) => {
                handshake::handle_hello(self, peer, hello, crypto)
            }
            wire::handshake::ArchivedHandshakeRecord::HelloReply(reply) => {
                handshake::handle_hello_reply(self, peer, reply)
            }
            wire::handshake::ArchivedHandshakeRecord::Confirm(confirm) => {
                handshake::handle_confirm(self, peer, confirm, crypto)
            }
            wire::handshake::ArchivedHandshakeRecord::Ready(ready) => {
                handshake::handle_ready(self, peer, header, ready)
            }
        }
    }

    fn handle_heartbeat(
        &mut self,
        header: &QlHeader,
        encrypted: &mut ArchivedEncryptedMessage,
        crypto: &impl QlCrypto,
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
        self.record_activity();
        if should_reply {
            self.send_heartbeat_message(crypto);
        }
        self.emit_peer_status();
    }

    fn fail_handshake(&mut self, error: QlError) {
        if let Some(entry) = self.peer.as_mut() {
            if matches!(
                entry.session,
                PeerSession::Initiator { .. } | PeerSession::Responder { .. }
            ) {
                entry.session = PeerSession::Disconnected;
            }
        }
        self.emit_peer_status();
        self.drop_outbound();
        self.abort_streams(error);
    }

    fn handle_handshake_retry_timeout(&mut self) {
        enum RetryAction {
            Resend {
                token: Token,
                peer: XID,
                deadline: Instant,
                record: wire::handshake::HandshakeRecord,
            },
            Fail,
            Ignore,
        }

        let now = self.state.now;
        let action = {
            let Some(entry) = self.peer.as_mut() else {
                return;
            };
            let peer = entry.peer;
            match &mut entry.session {
                PeerSession::Initiator {
                    handshake_token,
                    hello,
                    deadline,
                    stage:
                        HandshakeInitiator::WaitingHelloReply {
                            retry_count,
                            retry_at,
                        },
                    ..
                } if retry_at.is_some_and(|at| at <= now) => {
                    let token = *handshake_token;
                    *retry_at = None;
                    if *retry_count >= self.config.max_handshake_retries {
                        RetryAction::Fail
                    } else {
                        *retry_count = retry_count.saturating_add(1);
                        RetryAction::Resend {
                            token,
                            peer,
                            deadline: *deadline,
                            record: wire::handshake::HandshakeRecord::Hello(hello.clone()),
                        }
                    }
                }
                PeerSession::Initiator {
                    handshake_token,
                    deadline,
                    stage:
                        HandshakeInitiator::WaitingReady {
                            confirm,
                            retry_count,
                            retry_at,
                            ..
                        },
                    ..
                } if retry_at.is_some_and(|at| at <= now) => {
                    let token = *handshake_token;
                    *retry_at = None;
                    if *retry_count >= self.config.max_handshake_retries {
                        RetryAction::Fail
                    } else {
                        *retry_count = retry_count.saturating_add(1);
                        RetryAction::Resend {
                            token,
                            peer,
                            deadline: *deadline,
                            record: wire::handshake::HandshakeRecord::Confirm(confirm.clone()),
                        }
                    }
                }
                PeerSession::Responder {
                    handshake_token,
                    reply,
                    deadline,
                    stage:
                        HandshakeResponder::WaitingConfirm {
                            retry_count,
                            retry_at,
                            ..
                        },
                    ..
                } if retry_at.is_some_and(|at| at <= now) => {
                    let token = *handshake_token;
                    *retry_at = None;
                    if *retry_count >= self.config.max_handshake_retries {
                        RetryAction::Fail
                    } else {
                        *retry_count = retry_count.saturating_add(1);
                        RetryAction::Resend {
                            token,
                            peer,
                            deadline: *deadline,
                            record: wire::handshake::HandshakeRecord::HelloReply(reply.clone()),
                        }
                    }
                }
                _ => RetryAction::Ignore,
            }
        };

        match action {
            RetryAction::Resend {
                token,
                peer,
                deadline,
                record,
            } => {
                if self.handshake_write_pending(token) {
                    return;
                }
                handshake::enqueue_handshake_record(self, token, deadline, peer, record);
            }
            RetryAction::Fail => self.fail_handshake(QlError::Timeout),
            RetryAction::Ignore => {}
        }
    }

    fn abort_streams(&mut self, error: QlError) {
        stream::abort_streams(self, error);
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

    fn handshake_retry_deadline(&self) -> Option<Instant> {
        let entry = self.peer.as_ref()?;
        match &entry.session {
            PeerSession::Initiator {
                stage: HandshakeInitiator::WaitingHelloReply { retry_at, .. },
                ..
            }
            | PeerSession::Initiator {
                stage: HandshakeInitiator::WaitingReady { retry_at, .. },
                ..
            }
            | PeerSession::Responder {
                stage: HandshakeResponder::WaitingConfirm { retry_at, .. },
                ..
            } => *retry_at,
            PeerSession::Disconnected
            | PeerSession::Responder {
                stage: HandshakeResponder::SendingReady { .. },
                ..
            }
            | PeerSession::Connected { .. } => None,
        }
    }

    fn is_replayed_control(&mut self, peer: XID, meta: ControlMeta) -> bool {
        self.state
            .replay_cache
            .check_and_store_valid_until(ReplayKey::new(peer, meta.packet_id), meta.valid_until)
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

    fn connected_session_for_token(
        &self,
        token: Option<Token>,
    ) -> Option<(SymmetricKey, Option<RecentReady>)> {
        let token = token?;
        self.peer.as_ref().and_then(|entry| match &entry.session {
            PeerSession::Responder {
                hello,
                reply,
                deadline,
                handshake_token,
                stage: HandshakeResponder::SendingReady { session_key, ready },
            } if *handshake_token == token => Some((
                session_key.clone(),
                Some(RecentReady {
                    hello: hello.clone(),
                    reply: reply.clone(),
                    ready: ready.clone(),
                    expires_at: *deadline,
                }),
            )),
            _ => None,
        })
    }

    fn handshake_write_pending(&self, token: Token) -> bool {
        self.state
            .active_writes
            .values()
            .any(|active| active.token == Some(token))
            || self
                .state
                .control_outbound
                .iter()
                .any(|message| message.token == token)
    }

    fn clear_handshake_retry_at(&mut self, token: Token) {
        let Some(entry) = self.peer.as_mut() else {
            return;
        };
        match &mut entry.session {
            PeerSession::Initiator {
                handshake_token,
                stage: HandshakeInitiator::WaitingHelloReply { retry_at, .. },
                ..
            } if *handshake_token == token => *retry_at = None,
            PeerSession::Initiator {
                handshake_token,
                stage: HandshakeInitiator::WaitingReady { retry_at, .. },
                ..
            } if *handshake_token == token => *retry_at = None,
            PeerSession::Responder {
                handshake_token,
                stage: HandshakeResponder::WaitingConfirm { retry_at, .. },
                ..
            } if *handshake_token == token => *retry_at = None,
            _ => {}
        }
    }

    fn schedule_handshake_retry_after_write(&mut self, token: Token) {
        if self.config.handshake_retry_interval.is_zero() || self.config.max_handshake_retries == 0
        {
            return;
        }
        let now = self.state.now;
        let retry_at = now + self.config.handshake_retry_interval;
        let Some(entry) = self.peer.as_mut() else {
            return;
        };
        match &mut entry.session {
            PeerSession::Initiator {
                handshake_token,
                stage:
                    HandshakeInitiator::WaitingHelloReply {
                        retry_at: stage_retry_at,
                        ..
                    },
                ..
            } if *handshake_token == token => {
                *stage_retry_at = Some(retry_at);
            }
            PeerSession::Initiator {
                handshake_token,
                stage:
                    HandshakeInitiator::WaitingReady {
                        retry_at: stage_retry_at,
                        ..
                    },
                ..
            } if *handshake_token == token => {
                *stage_retry_at = Some(retry_at);
            }
            PeerSession::Responder {
                handshake_token,
                stage:
                    HandshakeResponder::WaitingConfirm {
                        retry_at: stage_retry_at,
                        ..
                    },
                ..
            } if *handshake_token == token => {
                *stage_retry_at = Some(retry_at);
            }
            _ => {}
        }
    }

    fn peer_session(&self) -> Option<(XID, SymmetricKey)> {
        self.peer.as_ref().and_then(|peer| {
            peer.session
                .session_key()
                .map(|key| (peer.peer, key.clone()))
        })
    }

    // todo: this is called in too many places
    fn sync_stream_namespace(&mut self) {
        use crate::stream::StreamNamespace;
        let namespace = self
            .peer
            .as_ref()
            .map(|peer| StreamNamespace::for_local(self.identity.xid, peer.peer))
            .unwrap_or(crate::stream::StreamNamespace::Low);
        self.streams.set_local_namespace(namespace);
    }

    fn issue_write(
        &mut self,
        kind: OutboundWriteKind,
        token: Option<Token>,
        bytes: Vec<u8>,
    ) -> OutboundWrite {
        let id = WriteId(self.state.active_writes.insert(ActiveWrite { token, kind }));
        OutboundWrite { id, bytes }
    }

    fn take_next_control_write(&mut self) -> Option<OutboundWrite> {
        while let Some(message) = self.state.control_outbound.pop_front() {
            return Some(self.issue_write(
                OutboundWriteKind::Control,
                Some(message.token),
                message.bytes,
            ));
        }
        None
    }

    fn send_heartbeat_message(&mut self, crypto: &impl QlCrypto) {
        let Some(peer) = self.peer.as_ref().map(|peer| peer.peer) else {
            return;
        };
        let now = self.state.now;
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

    fn record_activity(&mut self) {
        let now = self.state.now;
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
}

fn encrypted_message_nonce(crypto: &impl QlCrypto) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    crypto.fill_random_bytes(&mut nonce);
    nonce
}
