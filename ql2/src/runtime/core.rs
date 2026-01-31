use std::{
    cmp::Reverse, collections::binary_heap::PeekMut, future::Future, task::Poll, time::Instant,
};

use bc_components::{EncapsulationPublicKey, XID};
use dcbor::CBOR;
use futures_lite::future::poll_fn;

use crate::{
    crypto::{handshake, heartbeat, message, pair},
    platform::{QlPlatform, QlPlatformExt},
    runtime::{
        internal::{
            next_timeout_deadline, now_secs, peer_hello_wins, HelloAction, InFlightWrite,
            KeepAliveState, LoopStep, OutboundMessage, PendingEntry, RuntimeCommand, RuntimeState,
            TimeoutEntry, TimeoutKind,
        },
        HandlerEvent, InboundEvent, InboundRequest, InitiatorStage, KeepAliveConfig, PeerSession,
        Responder, Runtime, Token,
    },
    wire::{
        handshake::HandshakeRecord,
        heartbeat::HeartbeatBody,
        message::{MessageBody, MessageKind, Nack},
        pair::PairRequestRecord,
        QlHeader, QlPayload, QlRecord,
    },
    MessageId, QlError, RouteId,
};

impl<P: QlPlatform> Runtime<P> {
    pub async fn run(self) {
        let mut state = RuntimeState::new();
        let mut in_flight: Option<InFlightWrite<'_>> = None;
        while !self.rx.is_closed() {
            if in_flight.is_none() {
                in_flight = self.start_next_write(&mut state);
            }
            let step = self.next_step(&state, in_flight.as_mut()).await;
            match step {
                LoopStep::Event(command) => match command {
                    RuntimeCommand::RegisterPeer {
                        peer,
                        signing_key,
                        encapsulation_key,
                    } => {
                        self.handle_register_peer(&mut state, peer, signing_key, encapsulation_key);
                    }
                    RuntimeCommand::Connect { peer } => {
                        self.handle_connect(&mut state, peer);
                    }
                    RuntimeCommand::SendRequest {
                        recipient,
                        route_id,
                        payload,
                        respond_to,
                        config,
                    } => {
                        self.handle_send_request(
                            &mut state, recipient, route_id, payload, respond_to, config,
                        );
                    }
                    RuntimeCommand::SendEvent {
                        recipient,
                        route_id,
                        payload,
                    } => {
                        self.handle_send_event(&mut state, recipient, route_id, payload);
                    }
                    RuntimeCommand::SendResponse {
                        id,
                        recipient,
                        payload,
                        kind,
                    } => {
                        self.handle_send_response(&mut state, id, recipient, payload, kind);
                    }
                    RuntimeCommand::Incoming(bytes) => {
                        self.handle_incoming(&mut state, bytes);
                    }
                },
                LoopStep::Timeout => {
                    self.handle_timeouts(&mut state);
                }
                LoopStep::WriteDone {
                    peer,
                    token,
                    message_id,
                    result,
                } => {
                    in_flight = None;
                    self.handle_write_done(&mut state, peer, token, message_id, result);
                }
                LoopStep::Quit => break,
            }
        }
    }

    fn start_next_write<'a>(&'a self, state: &mut RuntimeState) -> Option<InFlightWrite<'a>> {
        let Some(message) = state.outbound.pop_front() else {
            return None;
        };
        Some(InFlightWrite {
            peer: message.peer,
            token: message.token,
            message_id: message.message_id,
            future: self.platform.write_message(message.bytes),
        })
    }

    async fn next_step<'a>(
        &'a self,
        state: &RuntimeState,
        mut in_flight: Option<&mut InFlightWrite<'a>>,
    ) -> LoopStep {
        let recv_future = self.rx.recv();
        futures_lite::pin!(recv_future);

        let mut sleep_future = next_timeout_deadline(state).map(|deadline| {
            let timeout = deadline.saturating_duration_since(Instant::now());
            self.platform.sleep(timeout)
        });

        poll_fn(|cx| {
            if let Some(in_flight) = in_flight.as_mut() {
                if let Poll::Ready(result) = in_flight.future.as_mut().poll(cx) {
                    return Poll::Ready(LoopStep::WriteDone {
                        peer: in_flight.peer,
                        token: in_flight.token,
                        message_id: in_flight.message_id,
                        result,
                    });
                }
            }

            if let Some(future) = sleep_future.as_mut() {
                if let Poll::Ready(()) = future.as_mut().poll(cx) {
                    return Poll::Ready(LoopStep::Timeout);
                }
            }

            recv_future.as_mut().poll(cx).map(|res| match res {
                Ok(event) => LoopStep::Event(event),
                Err(_) => LoopStep::Quit,
            })
        })
        .await
    }

    fn handle_connect(&self, state: &mut RuntimeState, peer: XID) {
        let encapsulation_key = match state.peers.peer(peer) {
            Some(entry) => match &entry.session {
                PeerSession::Connected { .. }
                | PeerSession::Initiator { .. }
                | PeerSession::Responder { .. } => {
                    return;
                }
                PeerSession::Disconnected => entry.encapsulation_key.clone(),
            },
            None => return,
        };

        let (hello, session_key) = match handshake::build_hello(
            &self.platform,
            self.platform.xid(),
            peer,
            &encapsulation_key,
        ) {
            Ok(result) => result,
            Err(_) => return,
        };

        let deadline = Instant::now() + self.config.handshake_timeout;
        let token = state.next_token();
        if let Some(entry) = state.peers.peer_mut(peer) {
            entry.session = PeerSession::Initiator {
                handshake_token: token,
                hello: hello.clone(),
                session_key,
                deadline,
                stage: InitiatorStage::WaitingHelloReply,
            };
            self.platform.handle_peer_status(peer, &entry.session);
        }

        let message = QlRecord {
            header: QlHeader {
                sender: self.platform.xid(),
                recipient: peer,
            },
            payload: QlPayload::Handshake(HandshakeRecord::Hello(hello)),
        };
        let bytes = CBOR::from(message).to_cbor_data();
        self.enqueue_handshake_message(state, peer, token, deadline, bytes);
    }

    fn handle_register_peer(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        signing_key: bc_components::SigningPublicKey,
        encapsulation_key: EncapsulationPublicKey,
    ) {
        let entry = state
            .peers
            .upsert_peer(peer, signing_key, encapsulation_key);
        if let PeerSession::Disconnected = entry.session {
            self.platform.handle_peer_status(peer, &entry.session);
        }
    }

    fn handle_send_request(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
        respond_to: oneshot::Sender<Result<CBOR, QlError>>,
        config: super::RequestConfig,
    ) {
        let id = state.next_message_id();
        let timeout = config
            .timeout
            .unwrap_or(self.config.default_request_timeout);
        if timeout.is_zero() {
            let _ = respond_to.send(Err(QlError::Timeout));
            return;
        }
        let Some(entry) = state.peers.peer(recipient) else {
            let _ = respond_to.send(Err(QlError::UnknownPeer(recipient)));
            return;
        };
        let session_key = match &entry.session {
            PeerSession::Connected { session_key, .. } => session_key,
            _ => {
                let _ = respond_to.send(Err(QlError::MissingSession(recipient)));
                return;
            }
        };
        let valid_until = now_secs().saturating_add(self.config.message_expiration.as_secs());
        let body = MessageBody {
            message_id: id,
            valid_until,
            kind: MessageKind::Request,
            route_id,
            payload,
        };
        let message = message::encrypt_message(
            QlHeader {
                sender: self.platform.xid(),
                recipient,
            },
            &session_key,
            body,
        );
        let bytes = CBOR::from(message).to_cbor_data();
        state.pending.insert(
            id,
            PendingEntry {
                recipient,
                tx: respond_to,
            },
        );
        state.timeouts.push(Reverse(TimeoutEntry {
            at: Instant::now() + timeout,
            kind: TimeoutKind::Request { id },
        }));
        let outbound_deadline = Instant::now() + self.config.message_expiration;
        self.enqueue_outbound(state, recipient, bytes, outbound_deadline, Some(id));
    }

    fn handle_send_event(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
    ) {
        let id = state.next_message_id();
        let Some(session_key) = state
            .peers
            .peer(recipient)
            .and_then(|p| p.session.session_key())
        else {
            return;
        };
        let valid_until = now_secs().saturating_add(self.config.message_expiration.as_secs());
        let body = MessageBody {
            message_id: id,
            valid_until,
            kind: MessageKind::Event,
            route_id,
            payload,
        };
        let message = message::encrypt_message(
            QlHeader {
                sender: self.platform.xid(),
                recipient,
            },
            &session_key,
            body,
        );
        let bytes = CBOR::from(message).to_cbor_data();
        let outbound_deadline = Instant::now() + self.config.message_expiration;
        self.enqueue_outbound(state, recipient, bytes, outbound_deadline, None);
    }

    fn handle_send_response(
        &self,
        state: &mut RuntimeState,
        id: MessageId,
        recipient: XID,
        payload: CBOR,
        kind: MessageKind,
    ) {
        let kind = match kind {
            MessageKind::Response | MessageKind::Nack => kind,
            _ => return,
        };
        let Some(session_key) = state
            .peers
            .peer(recipient)
            .and_then(|p| p.session.session_key())
        else {
            return;
        };

        let valid_until = now_secs().saturating_add(self.config.message_expiration.as_secs());
        let body = MessageBody {
            message_id: id,
            valid_until,
            kind,
            route_id: RouteId::new(0),
            payload,
        };
        let message = message::encrypt_message(
            QlHeader {
                sender: self.platform.xid(),
                recipient,
            },
            &session_key,
            body,
        );
        let bytes = CBOR::from(message).to_cbor_data();
        let outbound_deadline = Instant::now() + self.config.message_expiration;
        self.enqueue_outbound(state, recipient, bytes, outbound_deadline, None);
    }

    fn handle_incoming(&self, state: &mut RuntimeState, bytes: Vec<u8>) {
        let Ok(record) = CBOR::try_from_data(&bytes).and_then(QlRecord::try_from) else {
            return;
        };
        let QlRecord { header, payload } = record;
        if header.recipient != self.platform.xid() {
            return;
        }
        match payload {
            QlPayload::Handshake(message) => {
                self.handle_handshake(state, header, message);
            }
            QlPayload::Pair(request) => {
                self.handle_pairing(state, header, request);
            }
            QlPayload::Message(encrypted) => {
                self.handle_record(state, header, encrypted);
            }
            QlPayload::Heartbeat(encrypted) => {
                self.handle_heartbeat(state, header, encrypted);
            }
        }
    }

    fn handle_handshake(
        &self,
        state: &mut RuntimeState,
        header: QlHeader,
        message: HandshakeRecord,
    ) {
        match message {
            HandshakeRecord::Hello(hello) => {
                self.handle_hello(state, header, hello);
            }
            HandshakeRecord::HelloReply(reply) => {
                self.handle_hello_reply(state, header, reply);
            }
            HandshakeRecord::Confirm(confirm) => {
                self.handle_confirm(state, header, confirm);
            }
        }
    }

    fn handle_pairing(
        &self,
        state: &mut RuntimeState,
        header: QlHeader,
        request: PairRequestRecord,
    ) {
        let payload = match pair::decrypt_pair_request(&self.platform, &header, request) {
            Ok(payload) => payload,
            Err(_) => return,
        };
        let peer = XID::new(&payload.signing_pub_key);
        state
            .peers
            .upsert_peer(peer, payload.signing_pub_key, payload.encapsulation_pub_key);
        self.handle_connect(state, peer);
    }

    fn handle_record(
        &self,
        state: &mut RuntimeState,
        header: QlHeader,
        encrypted: bc_components::EncryptedMessage,
    ) {
        let peer = header.sender;
        let session_key = match state.peers.peer(peer) {
            Some(entry) => match &entry.session {
                PeerSession::Connected { session_key, .. } => session_key.clone(),
                _ => return,
            },
            None => return,
        };
        let record = match message::decrypt_message(&header, &encrypted, &session_key) {
            Ok(record) => record,
            // TODO: fix this
            Err(message::MessageError::Nack { .. }) => return,
            Err(message::MessageError::Error(_)) => return,
        };
        self.record_activity(state, peer);
        match record.kind {
            MessageKind::Response => {
                self.resolve_pending_ok(state, peer, record.message_id, record.payload);
            }
            MessageKind::Nack => {
                let nack = Nack::from(record.payload);
                self.resolve_pending_nack(state, peer, record.message_id, nack);
            }
            MessageKind::Request => {
                let Some(tx) = self.tx.upgrade() else {
                    return;
                };
                let responder = Responder::new(record.message_id, record.sender, tx);
                self.platform
                    .handle_inbound(HandlerEvent::Request(InboundRequest {
                        message: record,
                        respond_to: responder,
                    }));
            }
            MessageKind::Event => {
                self.platform
                    .handle_inbound(HandlerEvent::Event(InboundEvent { message: record }));
            }
        }
    }

    fn handle_heartbeat(
        &self,
        state: &mut RuntimeState,
        header: QlHeader,
        encrypted: bc_components::EncryptedMessage,
    ) {
        let peer = header.sender;
        let (session_key, should_reply) = {
            let Some(entry) = state.peers.peer(peer) else {
                return;
            };
            match &entry.session {
                PeerSession::Connected {
                    session_key,
                    keepalive,
                } => (session_key.clone(), !keepalive.pending),
                _ => return,
            }
        };
        if heartbeat::decrypt_heartbeat(&header, &encrypted, &session_key).is_err() {
            return;
        }
        self.record_activity(state, peer);
        if should_reply {
            self.send_heartbeat_message(state, peer, session_key);
        }
    }

    fn send_heartbeat_message(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        session_key: bc_components::SymmetricKey,
    ) {
        let message_id = state.next_message_id();
        let valid_until = now_secs().saturating_add(self.config.message_expiration.as_secs());
        let message = heartbeat::encrypt_heartbeat(
            QlHeader {
                sender: self.platform.xid(),
                recipient: peer,
            },
            &session_key,
            HeartbeatBody {
                message_id,
                valid_until,
            },
        );
        let bytes = CBOR::from(message).to_cbor_data();
        let outbound_deadline = Instant::now() + self.config.message_expiration;
        self.enqueue_outbound(state, peer, bytes, outbound_deadline, None);
    }

    fn keep_alive_config(&self) -> Option<KeepAliveConfig> {
        self.config
            .keep_alive
            .filter(|config| !config.interval.is_zero() && !config.timeout.is_zero())
    }

    fn record_activity(&self, state: &mut RuntimeState, peer: XID) {
        let Some(config) = self.keep_alive_config() else {
            return;
        };
        let token = state.next_token();
        let Some(entry) = state.peers.peer_mut(peer) else {
            return;
        };
        let PeerSession::Connected { keepalive, .. } = &mut entry.session else {
            return;
        };
        let now = Instant::now();
        keepalive.last_activity = Some(now);
        keepalive.pending = false;
        keepalive.token = token;
        state.timeouts.push(Reverse(TimeoutEntry {
            at: now + config.interval,
            kind: TimeoutKind::KeepAliveSend { peer, token },
        }));
    }

    fn drop_outbound_for_peer(&self, state: &mut RuntimeState, peer: XID) {
        state.outbound.retain(|message| {
            if message.peer == peer {
                if let Some(id) = message.message_id {
                    if let Some(entry) = state.pending.remove(&id) {
                        let _ = entry.tx.send(Err(QlError::SendFailed));
                    }
                }
                false
            } else {
                true
            }
        });
    }

    fn fail_pending_for_peer(&self, state: &mut RuntimeState, peer: XID) {
        state
            .pending
            .extract_if(|_id, entry| entry.recipient == peer)
            .for_each(|(_, entry)| {
                let _ = entry.tx.send(Err(QlError::SendFailed));
            });
    }

    fn resolve_pending_ok(
        &self,
        state: &mut RuntimeState,
        sender: XID,
        id: MessageId,
        payload: CBOR,
    ) {
        if let Some(entry) = state.pending.remove(&id) {
            if entry.recipient == sender {
                let _ = entry.tx.send(Ok(payload));
            }
        }
    }

    fn resolve_pending_nack(
        &self,
        state: &mut RuntimeState,
        sender: XID,
        id: MessageId,
        nack: Nack,
    ) {
        if let Some(entry) = state.pending.remove(&id) {
            if entry.recipient == sender {
                let _ = entry.tx.send(Err(QlError::Nack { id, nack }));
            }
        }
    }

    fn handle_hello(
        &self,
        state: &mut RuntimeState,
        header: QlHeader,
        hello: crate::wire::handshake::Hello,
    ) {
        let peer = header.sender;
        let action = match state.peers.peer(peer) {
            Some(entry) => match &entry.session {
                PeerSession::Initiator {
                    hello: local_hello, ..
                } => {
                    if peer_hello_wins(local_hello, self.platform.xid(), &hello, peer) {
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
                    if stored.nonce == hello.nonce {
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
                self.start_responder_handshake(state, peer, hello);
            }
            HelloAction::ResendReply { reply, deadline } => {
                let message = QlRecord {
                    header: QlHeader {
                        sender: self.platform.xid(),
                        recipient: peer,
                    },
                    payload: QlPayload::Handshake(HandshakeRecord::HelloReply(reply)),
                };
                let bytes = CBOR::from(message).to_cbor_data();
                self.enqueue_outbound(state, peer, bytes, deadline, None);
            }
            HelloAction::Ignore => {}
        }
    }

    fn handle_hello_reply(
        &self,
        state: &mut RuntimeState,
        header: QlHeader,
        reply: crate::wire::handshake::HelloReply,
    ) {
        let peer = header.sender;
        let (hello, initiator_secret, stage, responder_signing_key) = match state.peers.peer(peer) {
            Some(entry) => match &entry.session {
                PeerSession::Initiator {
                    hello,
                    session_key,
                    stage,
                    ..
                } => (
                    hello.clone(),
                    session_key.clone(),
                    *stage,
                    entry.signing_key.clone(),
                ),
                _ => return,
            },
            None => return,
        };

        if stage != InitiatorStage::WaitingHelloReply {
            return;
        }

        let confirm = match handshake::build_confirm(
            &self.platform,
            self.platform.xid(),
            peer,
            &responder_signing_key,
            &hello,
            &reply,
            &initiator_secret,
        ) {
            Ok((confirm, session_key)) => {
                if let Some(entry) = state.peers.peer_mut(peer) {
                    entry.session = PeerSession::Connected {
                        session_key,
                        keepalive: KeepAliveState::new(),
                    };
                    self.platform.handle_peer_status(peer, &entry.session);
                }
                self.record_activity(state, peer);
                confirm
            }
            Err(_) => {
                if let Some(entry) = state.peers.peer_mut(peer) {
                    entry.session = PeerSession::Disconnected;
                    self.platform.handle_peer_status(peer, &entry.session);
                }
                return;
            }
        };

        let message = QlRecord {
            header: QlHeader {
                sender: self.platform.xid(),
                recipient: peer,
            },
            payload: QlPayload::Handshake(HandshakeRecord::Confirm(confirm)),
        };
        let bytes = CBOR::from(message).to_cbor_data();
        let deadline = Instant::now() + self.config.handshake_timeout;
        self.enqueue_outbound(state, peer, bytes, deadline, None);
    }

    fn handle_confirm(
        &self,
        state: &mut RuntimeState,
        header: QlHeader,
        confirm: crate::wire::handshake::Confirm,
    ) {
        let peer = header.sender;
        let (hello, reply, secrets, initiator_signing_key) = match state.peers.peer(peer) {
            Some(entry) => match &entry.session {
                PeerSession::Responder {
                    hello,
                    reply,
                    secrets,
                    ..
                } => (
                    hello.clone(),
                    reply.clone(),
                    secrets.clone(),
                    entry.signing_key.clone(),
                ),
                _ => return,
            },
            None => return,
        };

        match handshake::finalize_confirm(
            peer,
            self.platform.xid(),
            &initiator_signing_key,
            &hello,
            &reply,
            &confirm,
            &secrets,
        ) {
            Ok(session_key) => {
                if let Some(entry) = state.peers.peer_mut(peer) {
                    entry.session = PeerSession::Connected {
                        session_key,
                        keepalive: KeepAliveState::new(),
                    };
                    self.platform.handle_peer_status(peer, &entry.session);
                }
                self.record_activity(state, peer);
            }
            Err(_) => {
                if let Some(entry) = state.peers.peer_mut(peer) {
                    entry.session = PeerSession::Disconnected;
                    self.platform.handle_peer_status(peer, &entry.session);
                }
            }
        }
    }

    fn start_responder_handshake(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        hello: crate::wire::handshake::Hello,
    ) {
        let encapsulation_key = match state.peers.peer(peer) {
            Some(entry) => entry.encapsulation_key.clone(),
            None => return,
        };
        let (reply, secrets) = match handshake::respond_hello(
            &self.platform,
            peer,
            self.platform.xid(),
            &encapsulation_key,
            &hello,
        ) {
            Ok(result) => result,
            Err(_) => {
                if let Some(entry) = state.peers.peer_mut(peer) {
                    entry.session = PeerSession::Disconnected;
                    self.platform.handle_peer_status(peer, &entry.session);
                }
                return;
            }
        };

        let deadline = Instant::now() + self.config.handshake_timeout;
        let token = state.next_token();
        if let Some(entry) = state.peers.peer_mut(peer) {
            entry.session = PeerSession::Responder {
                handshake_token: token,
                hello: hello.clone(),
                reply: reply.clone(),
                secrets,
                deadline,
            };
            self.platform.handle_peer_status(peer, &entry.session);
        }

        let message = QlRecord {
            header: QlHeader {
                sender: self.platform.xid(),
                recipient: peer,
            },
            payload: QlPayload::Handshake(HandshakeRecord::HelloReply(reply)),
        };
        let bytes = CBOR::from(message).to_cbor_data();
        self.enqueue_handshake_message(state, peer, token, deadline, bytes);
    }

    fn enqueue_handshake_message(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        token: Token,
        deadline: Instant,
        bytes: Vec<u8>,
    ) {
        state.outbound.push_back(OutboundMessage {
            peer,
            token,
            message_id: None,
            bytes,
        });
        state.timeouts.push(Reverse(TimeoutEntry {
            at: deadline,
            kind: TimeoutKind::Handshake { peer, token },
        }));
        state.timeouts.push(Reverse(TimeoutEntry {
            at: deadline,
            kind: TimeoutKind::Outbound { token },
        }));
    }

    fn enqueue_outbound(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        bytes: Vec<u8>,
        deadline: Instant,
        message_id: Option<MessageId>,
    ) {
        let token = state.next_token();
        state.outbound.push_back(OutboundMessage {
            peer,
            token,
            message_id,
            bytes,
        });
        state.timeouts.push(Reverse(TimeoutEntry {
            at: deadline,
            kind: TimeoutKind::Outbound { token },
        }));
    }

    fn handle_timeouts(&self, state: &mut RuntimeState) {
        let now = Instant::now();
        loop {
            let Some(entry) = state.timeouts.peek_mut().filter(|e| e.0.at <= now) else {
                break;
            };
            let entry = PeekMut::pop(entry).0;
            match entry.kind {
                TimeoutKind::Outbound { token } => {
                    let mut message_id = None;
                    state.outbound.retain(|message| {
                        if message.token == token {
                            message_id = message.message_id;
                            false
                        } else {
                            true
                        }
                    });
                    if let Some(id) = message_id {
                        if let Some(entry) = state.pending.remove(&id) {
                            let _ = entry.tx.send(Err(QlError::SendFailed));
                        }
                    }
                }
                TimeoutKind::Handshake { peer, token } => {
                    let Some(entry) = state.peers.peer(peer) else {
                        continue;
                    };
                    let should_disconnect = match &entry.session {
                        PeerSession::Initiator {
                            handshake_token, ..
                        }
                        | PeerSession::Responder {
                            handshake_token, ..
                        } => *handshake_token == token,
                        _ => false,
                    };
                    if should_disconnect {
                        if let Some(entry) = state.peers.peer_mut(peer) {
                            entry.session = PeerSession::Disconnected;
                            self.platform.handle_peer_status(peer, &entry.session);
                        }
                        state.outbound.retain(|message| message.peer != peer);
                    }
                }
                TimeoutKind::Request { id } => {
                    if let Some(entry) = state.pending.remove(&id) {
                        let _ = entry.tx.send(Err(QlError::Timeout));
                    }
                }
                TimeoutKind::KeepAliveSend { peer, token } => {
                    let Some(config) = self.keep_alive_config() else {
                        continue;
                    };
                    let session_key = {
                        let Some(entry) = state.peers.peer(peer) else {
                            continue;
                        };
                        let PeerSession::Connected {
                            session_key,
                            keepalive,
                        } = &entry.session
                        else {
                            continue;
                        };
                        if keepalive.token == token && !keepalive.pending {
                            session_key.clone()
                        } else {
                            continue;
                        }
                    };
                    self.send_heartbeat_message(state, peer, session_key);
                    if let Some(entry) = state.peers.peer_mut(peer) {
                        if let PeerSession::Connected { keepalive, .. } = &mut entry.session {
                            if keepalive.token == token {
                                keepalive.pending = true;
                            }
                        }
                    }
                    state.timeouts.push(Reverse(TimeoutEntry {
                        at: now + config.timeout,
                        kind: TimeoutKind::KeepAliveTimeout { peer, token },
                    }));
                }
                TimeoutKind::KeepAliveTimeout { peer, token } => {
                    let Some(entry) = state.peers.peer(peer) else {
                        continue;
                    };

                    let should_disconnect = match &entry.session {
                        PeerSession::Connected { keepalive, .. } => {
                            keepalive.token == token && keepalive.pending
                        }
                        _ => false,
                    };

                    if should_disconnect {
                        if let Some(entry) = state.peers.peer_mut(peer) {
                            entry.session = PeerSession::Disconnected;
                            self.platform.handle_peer_status(peer, &entry.session);
                        }
                        self.drop_outbound_for_peer(state, peer);
                        self.fail_pending_for_peer(state, peer);
                    }
                }
            }
        }
    }

    fn handle_write_done(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        token: Token,
        message_id: Option<MessageId>,
        result: Result<(), QlError>,
    ) {
        if result.is_ok() {
            return;
        }

        if let Some(id) = message_id {
            if let Some(entry) = state.pending.remove(&id) {
                let _ = entry.tx.send(Err(QlError::SendFailed));
            }
        }
        let should_disconnect = match state.peers.peer(peer).map(|entry| &entry.session) {
            Some(PeerSession::Initiator {
                handshake_token, ..
            }) if *handshake_token == token => true,
            Some(PeerSession::Responder {
                handshake_token, ..
            }) if *handshake_token == token => true,
            _ => false,
        };
        if should_disconnect {
            if let Some(entry) = state.peers.peer_mut(peer) {
                entry.session = PeerSession::Disconnected;
                self.platform.handle_peer_status(peer, &entry.session);
            }
            state.outbound.retain(|message| message.peer != peer);
        }
    }
}
