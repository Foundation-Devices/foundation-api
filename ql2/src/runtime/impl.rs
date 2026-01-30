use std::{cmp::Reverse, future::Future, task::Poll, time::Instant};

use bc_components::{EncapsulationPublicKey, XID};
use dcbor::CBOR;
use futures_lite::future::poll_fn;

use crate::{
    crypto::{handshake, message, pair},
    platform::{QlPlatform, QlPlatformExt},
    runtime::{
        internal::{
            now_secs, next_timeout_deadline, peer_hello_wins, HelloAction, InFlightWrite, LoopStep,
            OutboundMessage, PendingEntry, RuntimeState, TimeoutEntry, TimeoutKind,
        },
        HandlerEvent, InboundEvent, InboundRequest, InitiatorStage, PeerSession, Responder,
        Runtime, RuntimeCommand, Token,
    },
    wire::{
        handshake::HandshakeRecord,
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
        loop {
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

        let step = poll_fn(|cx| {
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

            match recv_future.as_mut().poll(cx) {
                Poll::Ready(Ok(event)) => Poll::Ready(LoopStep::Event(event)),
                Poll::Ready(Err(_)) => Poll::Ready(LoopStep::Quit),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;
        step
    }

    fn handle_connect(&self, state: &mut RuntimeState, peer: XID) {
        let encapsulation_key = match state.peer(peer) {
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
        if let Some(entry) = state.peer_mut(peer) {
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
        let entry = state.upsert_peer(peer, signing_key, encapsulation_key);
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
        let session_key = match state.peer(recipient) {
            Some(entry) => match &entry.session {
                PeerSession::Connected { session_key } => session_key.clone(),
                _ => {
                    let _ = respond_to.send(Err(QlError::MissingSession(recipient)));
                    return;
                }
            },
            None => {
                let _ = respond_to.send(Err(QlError::UnknownPeer(recipient)));
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
        let session_key = match state.peer(recipient) {
            Some(entry) => match &entry.session {
                PeerSession::Connected { session_key } => session_key.clone(),
                _ => return,
            },
            None => return,
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
        let session_key = match state.peer(recipient) {
            Some(entry) => match &entry.session {
                PeerSession::Connected { session_key } => session_key.clone(),
                _ => return,
            },
            None => return,
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
        state.upsert_peer(peer, payload.signing_pub_key, payload.encapsulation_pub_key);
        self.handle_connect(state, peer);
    }

    fn handle_record(
        &self,
        state: &mut RuntimeState,
        header: QlHeader,
        encrypted: bc_components::EncryptedMessage,
    ) {
        let peer = header.sender;
        let session_key = match state.peer(peer) {
            Some(entry) => match &entry.session {
                PeerSession::Connected { session_key } => session_key.clone(),
                _ => return,
            },
            None => return,
        };
        let record = match message::decrypt_message(&header, &encrypted, &session_key) {
            Ok(record) => record,
            Err(message::MessageError::Nack { .. }) => return,
            Err(message::MessageError::Error(_)) => return,
        };
        match record.kind {
            MessageKind::Response => {
                self.resolve_pending_ok(state, peer, record.message_id, record.payload);
            }
            MessageKind::Nack => {
                let nack = Nack::from(record.payload);
                self.resolve_pending_nack(state, peer, record.message_id, nack);
            }
            MessageKind::Request => {
                let responder = Responder::new(record.message_id, record.sender, self.tx.clone());
                self.platform.handle_inbound(HandlerEvent::Request(InboundRequest {
                    message: record,
                    respond_to: responder,
                }));
            }
            MessageKind::Event => {
                self.platform.handle_inbound(HandlerEvent::Event(InboundEvent { message: record }));
            }
        }
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
        let action = match state.peer(peer) {
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
        let (hello, initiator_secret, stage, responder_signing_key) = match state.peer(peer) {
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
                if let Some(entry) = state.peer_mut(peer) {
                    entry.session = PeerSession::Connected { session_key };
                    self.platform.handle_peer_status(peer, &entry.session);
                }
                confirm
            }
            Err(_) => {
                if let Some(entry) = state.peer_mut(peer) {
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
        let (hello, reply, secrets, initiator_signing_key) = match state.peer(peer) {
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
                if let Some(entry) = state.peer_mut(peer) {
                    entry.session = PeerSession::Connected { session_key };
                    self.platform.handle_peer_status(peer, &entry.session);
                }
            }
            Err(_) => {
                if let Some(entry) = state.peer_mut(peer) {
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
        let encapsulation_key = match state.peer(peer) {
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
                if let Some(entry) = state.peer_mut(peer) {
                    entry.session = PeerSession::Disconnected;
                    self.platform.handle_peer_status(peer, &entry.session);
                }
                return;
            }
        };

        let deadline = Instant::now() + self.config.handshake_timeout;
        let token = state.next_token();
        if let Some(entry) = state.peer_mut(peer) {
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
        while let Some(entry) = state.timeouts.peek() {
            if entry.0.at > now {
                break;
            }
            let entry = state.timeouts.pop().expect("timeout entry just peeked").0;
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
                    let should_disconnect = match state.peer(peer) {
                        Some(entry) => match &entry.session {
                            PeerSession::Initiator {
                                handshake_token, ..
                            }
                            | PeerSession::Responder {
                                handshake_token, ..
                            } => *handshake_token == token,
                            _ => false,
                        },
                        None => false,
                    };
                    if should_disconnect {
                        if let Some(entry) = state.peer_mut(peer) {
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
        match result {
            Ok(()) => {}
            Err(_) => {
                if let Some(id) = message_id {
                    if let Some(entry) = state.pending.remove(&id) {
                        let _ = entry.tx.send(Err(QlError::SendFailed));
                    }
                }
                let should_disconnect = match state.peer(peer).map(|entry| &entry.session) {
                    Some(PeerSession::Initiator {
                        handshake_token, ..
                    }) if *handshake_token == token => true,
                    Some(PeerSession::Responder {
                        handshake_token, ..
                    }) if *handshake_token == token => true,
                    _ => false,
                };
                if should_disconnect {
                    if let Some(entry) = state.peer_mut(peer) {
                        entry.session = PeerSession::Disconnected;
                        self.platform.handle_peer_status(peer, &entry.session);
                    }
                    state.outbound.retain(|message| message.peer != peer);
                }
            }
        }
    }
}
