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
        Engine, EngineEventSink, HandshakeInitiator, HandshakeResponder, KeepAliveConfig,
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
    pub fn open_stream(
        &mut self,
        now: Instant,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
        config: StreamConfig,
    ) -> Result<StreamId, QlError> {
        self.state.now = now;
        stream::open_stream(self, now, request_head, request_prefix, config)
    }

    pub fn bind_peer_inner(&mut self, peer: Peer, events: &mut impl EngineEventSink) {
        peer::handle_bind_peer(self, peer, events);
    }

    pub fn pair_inner(&mut self, now: Instant, crypto: &impl QlCrypto) {
        self.state.now = now;
        peer::handle_pair_local(self, now, crypto);
    }

    pub fn connect_inner(
        &mut self,
        now: Instant,
        crypto: &impl QlCrypto,
        events: &mut impl EngineEventSink,
    ) {
        self.state.now = now;
        handshake::handle_connect(self, now, crypto, events);
    }

    pub fn unpair_inner(&mut self, now: Instant, events: &mut impl EngineEventSink) {
        self.state.now = now;
        peer::handle_unpair_local(self, now, events);
    }

    pub fn write_stream_inner(
        &mut self,
        stream_id: StreamId,
        bytes: Vec<u8>,
    ) -> Result<(), QlError> {
        stream::handle_outbound_data(self, stream_id, bytes)
    }

    pub fn finish_stream_inner(&mut self, stream_id: StreamId) -> Result<(), QlError> {
        stream::handle_outbound_finished(self, stream_id)
    }

    pub fn close_stream_inner(
        &mut self,
        stream_id: StreamId,
        target: CloseTarget,
        code: CloseCode,
        payload: Vec<u8>,
    ) -> Result<(), QlError> {
        stream::handle_close_stream(self, stream_id, target, code, payload)
    }

    pub fn receive_inner(
        &mut self,
        now: Instant,
        bytes: Vec<u8>,
        crypto: &impl QlCrypto,
        events: &mut impl EngineEventSink,
    ) {
        self.state.now = now;
        self.handle_incoming(now, bytes, crypto, events);
    }

    pub fn take_next_write_inner(&mut self, crypto: &impl QlCrypto) -> Option<OutboundWrite> {
        self.take_next_control_write()
            .or_else(|| stream::take_next_stream_write(self, crypto))
    }

    pub fn complete_write_inner(
        &mut self,
        write_id: WriteId,
        result: Result<(), QlError>,
        events: &mut impl EngineEventSink,
    ) {
        let now = self.state.now;
        let Some(active) = self.state.active_writes.remove(write_id.0) else {
            return;
        };

        if let Err(error) = result {
            if let OutboundWriteKind::Stream(completion) = active.kind {
                stream::complete_stream_write(self, now, completion, Err(error.clone()), events);
            }

            if self.is_handshake_token(active.token) {
                if let Some(entry) = self.peer.as_mut() {
                    entry.session = PeerSession::Disconnected;
                }
                self.emit_peer_status(events);
                self.drop_outbound();
                self.abort_streams(error, events);
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
            self.emit_peer_status(events);
            self.record_activity(now);
        }

        if let Some(token) = active.token {
            self.schedule_handshake_retry_after_write(token, now);
        }

        if let OutboundWriteKind::Stream(completion) = active.kind {
            stream::complete_stream_write(self, now, completion, Ok(()), events);
        }
    }

    pub fn on_timer_inner(
        &mut self,
        now: Instant,
        crypto: &impl QlCrypto,
        events: &mut impl EngineEventSink,
    ) {
        self.state.now = now;
        self.handle_timeouts(now, crypto, events);
    }

    pub fn next_deadline_inner(&self) -> Option<Instant> {
        [
            self.state.next_deadline(),
            self.streams.next_deadline(),
            self.handshake_deadline(),
            self.keep_alive_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    pub fn abort_inner(&mut self, error: QlError, events: &mut impl EngineEventSink) {
        self.abort_streams(error, events);
    }
}

impl Engine {
    fn emit_peer_status(&self, events: &mut impl EngineEventSink) {
        if let Some(peer) = self.peer.as_ref() {
            events.peer_status_changed(peer.peer, peer.session.clone());
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
        events: &mut impl EngineEventSink,
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
                self.handle_handshake(now, sender, &header, message, crypto, events)
            }
            wire::ArchivedQlPayload::Stream(encrypted) => {
                stream::handle_stream(self, now, sender, &header, encrypted, events)
            }
            wire::ArchivedQlPayload::Heartbeat(encrypted) => {
                self.handle_heartbeat(now, &header, encrypted, crypto, events)
            }
            wire::ArchivedQlPayload::Pair(request) => {
                peer::handle_pairing(self, now, &header, request, crypto, events)
            }
            wire::ArchivedQlPayload::Unpair(unpair_record) => {
                peer::handle_unpair(self, sender, &header, unpair_record, events)
            }
        }
    }

    fn handle_handshake(
        &mut self,
        now: Instant,
        peer: XID,
        header: &QlHeader,
        message: &mut wire::handshake::ArchivedHandshakeRecord,
        crypto: &impl QlCrypto,
        events: &mut impl EngineEventSink,
    ) {
        match message {
            wire::handshake::ArchivedHandshakeRecord::Hello(hello) => {
                handshake::handle_hello(self, now, peer, hello, crypto, events)
            }
            wire::handshake::ArchivedHandshakeRecord::HelloReply(reply) => {
                handshake::handle_hello_reply(self, now, peer, reply)
            }
            wire::handshake::ArchivedHandshakeRecord::Confirm(confirm) => {
                handshake::handle_confirm(self, now, peer, confirm, crypto)
            }
            wire::handshake::ArchivedHandshakeRecord::Ready(ready) => {
                handshake::handle_ready(self, now, peer, header, ready, events)
            }
        }
    }

    fn handle_heartbeat(
        &mut self,
        now: Instant,
        header: &QlHeader,
        encrypted: &mut ArchivedEncryptedMessage,
        crypto: &impl QlCrypto,
        events: &mut impl EngineEventSink,
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
        self.emit_peer_status(events);
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

    fn schedule_handshake_retry_after_write(&mut self, token: Token, now: Instant) {
        if self.config.handshake_retry_interval.is_zero() || self.config.max_handshake_retries == 0
        {
            return;
        }
        let retry_at = now + self.config.handshake_retry_interval;
        let Some(entry) = self.peer.as_mut() else {
            return;
        };
        let scheduled = match &mut entry.session {
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
                true
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
                true
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
                true
            }
            _ => false,
        };
        if scheduled {
            self.state.schedule_handshake_retry(token, retry_at);
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

    fn fail_handshake(&mut self, error: QlError, events: &mut impl EngineEventSink) {
        if let Some(entry) = self.peer.as_mut() {
            if matches!(
                entry.session,
                PeerSession::Initiator { .. } | PeerSession::Responder { .. }
            ) {
                entry.session = PeerSession::Disconnected;
            }
        }
        self.emit_peer_status(events);
        self.drop_outbound();
        self.abort_streams(error, events);
    }

    fn handle_handshake_retry_timeout(&mut self, token: Token, events: &mut impl EngineEventSink) {
        enum RetryAction {
            Resend {
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
                } if *handshake_token == token && retry_at.is_some_and(|at| at <= now) => {
                    *retry_at = None;
                    if *retry_count >= self.config.max_handshake_retries {
                        RetryAction::Fail
                    } else {
                        *retry_count = retry_count.saturating_add(1);
                        RetryAction::Resend {
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
                } if *handshake_token == token && retry_at.is_some_and(|at| at <= now) => {
                    *retry_at = None;
                    if *retry_count >= self.config.max_handshake_retries {
                        RetryAction::Fail
                    } else {
                        *retry_count = retry_count.saturating_add(1);
                        RetryAction::Resend {
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
                } if *handshake_token == token && retry_at.is_some_and(|at| at <= now) => {
                    *retry_at = None;
                    if *retry_count >= self.config.max_handshake_retries {
                        RetryAction::Fail
                    } else {
                        *retry_count = retry_count.saturating_add(1);
                        RetryAction::Resend {
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
                peer,
                deadline,
                record,
            } => {
                if self.handshake_write_pending(token) {
                    return;
                }
                handshake::enqueue_handshake_record(self, token, deadline, peer, record);
            }
            RetryAction::Fail => self.fail_handshake(QlError::Timeout, events),
            RetryAction::Ignore => {}
        }
    }

    fn abort_streams(&mut self, error: QlError, events: &mut impl EngineEventSink) {
        stream::abort_streams(self, error, events);
    }

    pub fn handle_timeouts(
        &mut self,
        now: Instant,
        crypto: &impl QlCrypto,
        events: &mut impl EngineEventSink,
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
                TimeoutKind::HandshakeRetry { token } => {
                    self.handle_handshake_retry_timeout(token, events);
                }
            }
        }

        stream::handle_stream_timeouts(self, now, events);

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
            self.fail_handshake(QlError::Timeout, events);
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
            self.emit_peer_status(events);
            self.drop_outbound();
            self.abort_streams(QlError::SendFailed, events);
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
