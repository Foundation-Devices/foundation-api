use std::{
    cmp::Reverse, collections::binary_heap::PeekMut, future::Future, task::Poll, time::Instant,
};

use bc_components::{MLDSAPublicKey, MLKEMPublicKey, SigningPublicKey, XID};
use dcbor::CBOR;
use futures_lite::future::poll_fn;

use crate::{
    platform::{QlPlatform, QlPlatformExt},
    runtime::{
        internal::{
            next_timeout_deadline, now_secs, peer_hello_wins, HelloAction, InFlightWrite,
            InboundStreamDelivery, InboundStreamItem, InboundTransferOpen, InboundTransferState,
            KeepAliveState, LoopStep, OutboundAwaiting, OutboundMessage, OutboundPayload,
            OutboundStreamInput, OutboundTransferStage, OutboundTransferState, PendingEntry,
            PendingStreamEntry, RuntimeCommand, RuntimeState, TimeoutEntry, TimeoutKind,
        },
        replay_cache::{ReplayKey, ReplayNamespace},
        HandlerEvent, InboundByteStream, InboundEvent, InboundRequest, InboundUploadRequest,
        InitiatorStage, KeepAliveConfig, PeerSession, Responder, Runtime, Token,
    },
    wire::{
        handshake::{self, HandshakeRecord},
        heartbeat::{self, HeartbeatBody},
        message::{self, MessageBody, MessageKind, Nack},
        pair::{self, PairRequestRecord},
        transfer::{self, TransferBody, TransferFrame},
        unpair::{self, UnpairRecord},
        QlHeader, QlPayload, QlRecord,
    },
    MessageId, QlError, RouteId,
};

const TRANSFER_RETRY_LIMIT: u8 = 5;

impl<P: QlPlatform> Runtime<P> {
    pub async fn run(self) {
        let mut state = RuntimeState::new();
        for peer in self.platform.load_peers().await {
            state
                .peers
                .upsert_peer(peer.peer, peer.signing_key, peer.encapsulation_key);
        }
        let mut in_flight: Option<InFlightWrite<'_>> = None;
        while !self.rx.is_closed() {
            self.drive_outbound_transfers(&mut state);
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
                    RuntimeCommand::Unpair { peer } => {
                        self.handle_send_unpair(&mut state, peer);
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
                    RuntimeCommand::SendStreamRequest {
                        recipient,
                        route_id,
                        payload,
                        respond_to,
                        config,
                    } => {
                        self.handle_send_stream_request(
                            &mut state, recipient, route_id, payload, respond_to, config,
                        );
                    }
                    RuntimeCommand::SendUploadRequest {
                        recipient,
                        route_id,
                        payload,
                        respond_to,
                        chunk_rx,
                        start,
                        config,
                    } => {
                        self.handle_send_upload_request(
                            &mut state, recipient, route_id, payload, respond_to, chunk_rx, start,
                            config,
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
                    RuntimeCommand::StartResponseStream {
                        request_id,
                        recipient,
                        meta,
                        chunk_rx,
                    } => {
                        self.handle_start_response_stream(
                            &mut state, request_id, recipient, meta, chunk_rx,
                        );
                    }
                    RuntimeCommand::PollOutboundTransfer {
                        recipient,
                        transfer_id,
                    } => {
                        self.drive_outbound_transfer(&mut state, recipient, transfer_id);
                    }
                    RuntimeCommand::CancelOutboundTransfer {
                        recipient,
                        transfer_id,
                    } => {
                        self.handle_cancel_outbound_transfer(&mut state, recipient, transfer_id);
                    }
                    RuntimeCommand::CancelInboundTransfer {
                        sender,
                        transfer_id,
                    } => {
                        self.handle_cancel_inbound_transfer(&mut state, sender, transfer_id);
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
        while let Some(message) = state.outbound.pop_front() {
            let bytes = match message.payload {
                OutboundPayload::PreEncoded(bytes) => bytes,
                OutboundPayload::DeferredMessage(body) => {
                    let Some(session_key) = state
                        .peers
                        .peer(message.peer)
                        .and_then(|entry| entry.session.session_key())
                    else {
                        if let Some(id) = message.message_id {
                            if let Some(entry) = state.pending.remove(&id) {
                                let _ = entry.tx.send(Err(QlError::SendFailed));
                            }
                            if let Some(entry) = state.pending_stream.remove(&id) {
                                let _ = entry.tx.send(Err(QlError::SendFailed));
                            }
                        }
                        continue;
                    };
                    let message = message::encrypt_message(
                        QlHeader {
                            sender: self.platform.xid(),
                            recipient: message.peer,
                        },
                        session_key,
                        body,
                    );
                    CBOR::from(message).to_cbor_data()
                }
            };
            return Some(InFlightWrite {
                peer: message.peer,
                token: message.token,
                message_id: message.message_id,
                future: self.platform.write_message(bytes),
            });
        }
        None
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
        signing_key: MLDSAPublicKey,
        encapsulation_key: MLKEMPublicKey,
    ) {
        {
            let entry = state
                .peers
                .upsert_peer(peer, signing_key, encapsulation_key);
            if let PeerSession::Disconnected = entry.session {
                self.platform.handle_peer_status(peer, &entry.session);
            }
        }
        self.persist_peers(state);
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
        if !entry.session.is_connected() {
            let _ = respond_to.send(Err(QlError::MissingSession(recipient)));
            return;
        }
        let valid_until = now_secs().saturating_add(self.config.message_expiration.as_secs());
        let body = MessageBody {
            message_id: id,
            valid_until,
            kind: MessageKind::Request,
            route_id,
            payload,
        };
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
        self.enqueue_outbound(
            state,
            recipient,
            OutboundPayload::DeferredMessage(body),
            outbound_deadline,
            Some(id),
        );
    }

    fn handle_send_stream_request(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
        respond_to: oneshot::Sender<Result<InboundStreamDelivery, QlError>>,
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
        if !entry.session.is_connected() {
            let _ = respond_to.send(Err(QlError::MissingSession(recipient)));
            return;
        }
        let valid_until = now_secs().saturating_add(self.config.message_expiration.as_secs());
        let body = MessageBody {
            message_id: id,
            valid_until,
            kind: MessageKind::Request,
            route_id,
            payload,
        };
        state.pending_stream.insert(
            id,
            PendingStreamEntry {
                recipient,
                tx: respond_to,
            },
        );
        state.timeouts.push(Reverse(TimeoutEntry {
            at: Instant::now() + timeout,
            kind: TimeoutKind::Request { id },
        }));
        let outbound_deadline = Instant::now() + self.config.message_expiration;
        self.enqueue_outbound(
            state,
            recipient,
            OutboundPayload::DeferredMessage(body),
            outbound_deadline,
            Some(id),
        );
    }

    fn handle_send_upload_request(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
        respond_to: oneshot::Sender<Result<CBOR, QlError>>,
        chunk_rx: async_channel::Receiver<OutboundStreamInput>,
        start: oneshot::Sender<Result<MessageId, QlError>>,
        config: super::RequestConfig,
    ) {
        let timeout = config
            .timeout
            .unwrap_or(self.config.default_request_timeout);
        if timeout.is_zero() {
            let _ = start.send(Err(QlError::Timeout));
            return;
        }
        let Some(entry) = state.peers.peer(recipient) else {
            let _ = start.send(Err(QlError::UnknownPeer(recipient)));
            return;
        };
        if !entry.session.is_connected() {
            let _ = start.send(Err(QlError::MissingSession(recipient)));
            return;
        }

        let request_id = state.next_message_id();
        state.pending.insert(
            request_id,
            PendingEntry {
                recipient,
                tx: respond_to,
            },
        );
        state.timeouts.push(Reverse(TimeoutEntry {
            at: Instant::now() + timeout,
            kind: TimeoutKind::Request { id: request_id },
        }));

        let transfer_id = request_id;
        let key = (recipient, transfer_id);
        if state.outbound_transfers.contains_key(&key) {
            let _ = state.pending.remove(&request_id);
            let _ = start.send(Err(QlError::SendFailed));
            return;
        }

        state.outbound_transfers.insert(
            key,
            OutboundTransferState {
                request_id,
                peer: recipient,
                transfer_id,
                stage: OutboundTransferStage::Opening,
                next_seq: 1,
                open_route_id: Some(route_id),
                open_meta: Some(payload),
                chunk_rx,
                awaiting: None,
            },
        );

        let _ = start.send(Ok(request_id));
    }

    fn handle_send_event(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
    ) {
        let id = state.next_message_id();
        let Some(entry) = state.peers.peer(recipient) else {
            return;
        };
        if !entry.session.is_connected() {
            return;
        }
        let valid_until = now_secs().saturating_add(self.config.message_expiration.as_secs());
        let body = MessageBody {
            message_id: id,
            valid_until,
            kind: MessageKind::Event,
            route_id,
            payload,
        };
        let outbound_deadline = Instant::now() + self.config.message_expiration;
        self.enqueue_outbound(
            state,
            recipient,
            OutboundPayload::DeferredMessage(body),
            outbound_deadline,
            None,
        );
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
        let Some(entry) = state.peers.peer(recipient) else {
            return;
        };
        if !entry.session.is_connected() {
            return;
        }

        let valid_until = now_secs().saturating_add(self.config.message_expiration.as_secs());
        let body = MessageBody {
            message_id: id,
            valid_until,
            kind,
            route_id: RouteId(0),
            payload,
        };
        let outbound_deadline = Instant::now() + self.config.message_expiration;
        self.enqueue_outbound(
            state,
            recipient,
            OutboundPayload::DeferredMessage(body),
            outbound_deadline,
            None,
        );
    }

    fn handle_start_response_stream(
        &self,
        state: &mut RuntimeState,
        request_id: MessageId,
        recipient: XID,
        meta: CBOR,
        chunk_rx: async_channel::Receiver<OutboundStreamInput>,
    ) {
        if !matches!(
            state.peers.peer(recipient),
            Some(entry) if entry.session.is_connected()
        ) {
            return;
        }

        let transfer_id = request_id;
        let key = (recipient, transfer_id);
        if state.outbound_transfers.contains_key(&key) {
            return;
        }

        state.outbound_transfers.insert(
            key,
            OutboundTransferState {
                request_id,
                peer: recipient,
                transfer_id,
                stage: OutboundTransferStage::Opening,
                next_seq: 1,
                open_route_id: None,
                open_meta: Some(meta),
                chunk_rx,
                awaiting: None,
            },
        );
    }

    fn handle_cancel_outbound_transfer(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        transfer_id: MessageId,
    ) {
        let key = (recipient, transfer_id);
        let mut found = false;
        if let Some(transfer) = state.outbound_transfers.get_mut(&key) {
            found = true;
            transfer.stage = OutboundTransferStage::Cancelling;
            transfer.awaiting = None;
            transfer.chunk_rx.close();
        }
        if found {
            self.drive_outbound_transfer(state, recipient, transfer_id);
        }
    }

    fn handle_cancel_inbound_transfer(
        &self,
        state: &mut RuntimeState,
        sender: XID,
        transfer_id: MessageId,
    ) {
        if state
            .inbound_transfers
            .remove(&(sender, transfer_id))
            .is_some()
        {
            self.send_transfer_frame(state, sender, transfer_id, TransferFrame::Cancel, false);
        }
    }

    fn handle_send_unpair(&self, state: &mut RuntimeState, peer: XID) {
        if state.peers.peer(peer).is_none() {
            return;
        }
        let message = unpair::build_unpair_record(
            &self.platform,
            QlHeader {
                sender: self.platform.xid(),
                recipient: peer,
            },
            state.next_message_id(),
            now_secs().saturating_add(self.config.message_expiration.as_secs()),
        );
        let bytes = CBOR::from(message).to_cbor_data();
        self.unpair_peer(state, peer);
        let deadline = Instant::now() + self.config.message_expiration;
        self.enqueue_outbound(
            state,
            peer,
            OutboundPayload::PreEncoded(bytes),
            deadline,
            None,
        );
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
            QlPayload::Unpair(unpair) => {
                self.handle_unpair(state, header, unpair);
            }
            QlPayload::Message(encrypted) => {
                self.handle_record(state, header, encrypted);
            }
            QlPayload::Heartbeat(encrypted) => {
                self.handle_heartbeat(state, header, encrypted);
            }
            QlPayload::Transfer(encrypted) => {
                self.handle_transfer(state, header, encrypted);
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
        let peer = XID::new(SigningPublicKey::MLDSA(payload.signing_pub_key.clone()));
        state
            .peers
            .upsert_peer(peer, payload.signing_pub_key, payload.encapsulation_pub_key);
        self.persist_peers(state);
        self.handle_connect(state, peer);
    }

    fn handle_unpair(&self, state: &mut RuntimeState, header: QlHeader, record: UnpairRecord) {
        let peer = header.sender;
        let Some(signing_key) = state
            .peers
            .peer(peer)
            .map(|entry| entry.signing_key.clone())
        else {
            return;
        };
        if unpair::verify_unpair_record(&header, &record, &signing_key).is_err() {
            return;
        }
        let replay_key = ReplayKey::new(peer, ReplayNamespace::Peer, record.message_id);
        if state
            .replay_cache
            .check_and_store_valid_until(replay_key, record.valid_until)
        {
            return;
        }
        self.unpair_peer(state, peer);
    }

    fn unpair_peer(&self, state: &mut RuntimeState, peer: XID) {
        if state.peers.remove_peer(peer).is_none() {
            return;
        }
        self.drop_outbound_for_peer(state, peer);
        self.fail_pending_for_peer(state, peer);
        self.fail_pending_stream_for_peer(state, peer);
        self.abort_transfers_for_peer(state, peer, QlError::SendFailed);
        state.replay_cache.clear_peer(peer);
        self.platform
            .handle_peer_status(peer, &PeerSession::Disconnected);
        self.persist_peers(state);
    }

    fn persist_peers(&self, state: &RuntimeState) {
        self.platform.persist_peers(state.peers.all());
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
            Err(message::MessageError::Nack { id, nack, kind }) => {
                self.handle_message_nack(state, peer, id, nack, kind);
                return;
            }
            Err(message::MessageError::Error(_)) => return,
        };
        let namespace = match record.kind {
            MessageKind::Request | MessageKind::Event => ReplayNamespace::Peer,
            MessageKind::Response | MessageKind::Nack => ReplayNamespace::Local,
        };
        let replay_key = ReplayKey::new(peer, namespace, record.message_id);
        if state
            .replay_cache
            .check_and_store_valid_until(replay_key, record.valid_until)
        {
            return;
        }
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

    fn handle_message_nack(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        id: MessageId,
        nack: Nack,
        kind: MessageKind,
    ) {
        if kind != MessageKind::Request {
            return;
        }
        self.handle_send_response(state, id, peer, CBOR::from(nack), MessageKind::Nack);
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

    fn handle_transfer(
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
        let body = match transfer::decrypt_transfer(&header, &encrypted, &session_key) {
            Ok(body) => body,
            Err(_) => return,
        };

        let replay_key = ReplayKey::new(peer, ReplayNamespace::Transfer, body.message_id);
        if state
            .replay_cache
            .check_and_store_valid_until(replay_key, body.valid_until)
        {
            return;
        }

        self.record_activity(state, peer);
        self.handle_transfer_frame(state, peer, body.transfer_id, body.frame);
    }

    fn handle_transfer_frame(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        transfer_id: MessageId,
        frame: TransferFrame,
    ) {
        match frame {
            TransferFrame::OpenResponse { request_id, meta } => {
                self.handle_transfer_open_response(state, peer, transfer_id, request_id, meta);
            }
            TransferFrame::OpenRequest {
                request_id,
                route_id,
                meta,
            } => {
                self.handle_transfer_open_request(
                    state,
                    peer,
                    transfer_id,
                    request_id,
                    route_id,
                    meta,
                );
            }
            TransferFrame::Chunk { seq, data } => {
                self.handle_transfer_chunk(state, peer, transfer_id, seq, data);
            }
            TransferFrame::Finish { seq } => {
                self.handle_transfer_finish(state, peer, transfer_id, seq);
            }
            TransferFrame::Ack { next_seq } => {
                self.handle_transfer_ack(state, peer, transfer_id, next_seq);
            }
            TransferFrame::Cancel => {
                self.handle_transfer_cancel(state, peer, transfer_id);
            }
            TransferFrame::CancelAck => {
                self.handle_transfer_cancel_ack(state, peer, transfer_id);
            }
        }
    }

    fn handle_transfer_open_response(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        transfer_id: MessageId,
        request_id: MessageId,
        meta: CBOR,
    ) {
        let open = InboundTransferOpen::Response {
            request_id,
            meta: meta.clone(),
        };
        if self.handle_duplicate_transfer_open(state, peer, transfer_id, &open) {
            return;
        }

        let Some(pending) = state.pending_stream.remove(&request_id) else {
            self.send_transfer_frame(state, peer, transfer_id, TransferFrame::Cancel, true);
            return;
        };
        if pending.recipient != peer {
            let _ = pending.tx.send(Err(QlError::SendFailed));
            self.send_transfer_frame(state, peer, transfer_id, TransferFrame::Cancel, true);
            return;
        }

        let Some(tx) = self.tx.upgrade() else {
            let _ = pending.tx.send(Err(QlError::Cancelled));
            return;
        };

        let (chunk_tx, chunk_rx) = async_channel::bounded(1);

        let delivery = InboundStreamDelivery {
            peer,
            transfer_id,
            meta,
            rx: chunk_rx,
            tx,
        };
        if pending.tx.send(Ok(delivery)).is_err() {
            self.send_transfer_frame(state, peer, transfer_id, TransferFrame::Cancel, true);
            return;
        }

        state.inbound_transfers.insert(
            (peer, transfer_id),
            InboundTransferState {
                open,
                expected_seq: 1,
                chunk_tx,
            },
        );

        self.send_transfer_frame(
            state,
            peer,
            transfer_id,
            TransferFrame::Ack { next_seq: 1 },
            true,
        );
    }

    fn handle_transfer_open_request(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        transfer_id: MessageId,
        request_id: MessageId,
        route_id: RouteId,
        meta: CBOR,
    ) {
        let open = InboundTransferOpen::Request {
            request_id,
            route_id,
            meta: meta.clone(),
        };
        if self.handle_duplicate_transfer_open(state, peer, transfer_id, &open) {
            return;
        }

        let Some(tx) = self.tx.upgrade() else {
            self.send_transfer_frame(state, peer, transfer_id, TransferFrame::Cancel, true);
            return;
        };

        let (chunk_tx, chunk_rx) = async_channel::bounded(1);
        let responder = Responder::new(request_id, peer, tx.clone());
        let body = InboundByteStream::new(peer, transfer_id, chunk_rx, tx);
        self.platform
            .handle_inbound(HandlerEvent::UploadRequest(InboundUploadRequest {
                sender: peer,
                recipient: self.platform.xid(),
                route_id,
                message_id: request_id,
                meta,
                body,
                respond_to: responder,
            }));

        state.inbound_transfers.insert(
            (peer, transfer_id),
            InboundTransferState {
                open,
                expected_seq: 1,
                chunk_tx,
            },
        );

        self.send_transfer_frame(
            state,
            peer,
            transfer_id,
            TransferFrame::Ack { next_seq: 1 },
            true,
        );
    }

    fn handle_duplicate_transfer_open(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        transfer_id: MessageId,
        open: &InboundTransferOpen,
    ) -> bool {
        let key = (peer, transfer_id);
        let Some(existing) = state.inbound_transfers.get(&key) else {
            return false;
        };

        let frame = if &existing.open == open {
            TransferFrame::Ack { next_seq: 1 }
        } else {
            TransferFrame::Cancel
        };
        self.send_transfer_frame(state, peer, transfer_id, frame, true);
        true
    }

    fn handle_transfer_chunk(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        transfer_id: MessageId,
        seq: u32,
        data: Vec<u8>,
    ) {
        let key = (peer, transfer_id);
        let Some(mut transfer_state) = state.inbound_transfers.remove(&key) else {
            return;
        };

        if seq < transfer_state.expected_seq {
            self.send_transfer_frame(
                state,
                peer,
                transfer_id,
                TransferFrame::Ack {
                    next_seq: transfer_state.expected_seq,
                },
                true,
            );
            state.inbound_transfers.insert(key, transfer_state);
            return;
        }

        if seq > transfer_state.expected_seq {
            let _ = transfer_state.chunk_tx.try_send(InboundStreamItem::Error(
                QlError::TransferProtocol { id: transfer_id },
            ));
            transfer_state.chunk_tx.close();
            self.send_transfer_frame(state, peer, transfer_id, TransferFrame::Cancel, true);
            return;
        }

        match transfer_state
            .chunk_tx
            .try_send(InboundStreamItem::Chunk(data))
        {
            Ok(()) => {
                transfer_state.expected_seq = transfer_state.expected_seq.saturating_add(1);
                self.send_transfer_frame(
                    state,
                    peer,
                    transfer_id,
                    TransferFrame::Ack {
                        next_seq: transfer_state.expected_seq,
                    },
                    true,
                );
                state.inbound_transfers.insert(key, transfer_state);
            }
            Err(async_channel::TrySendError::Full(_)) => {
                state.inbound_transfers.insert(key, transfer_state);
            }
            Err(async_channel::TrySendError::Closed(_)) => {
                self.send_transfer_frame(state, peer, transfer_id, TransferFrame::Cancel, true);
            }
        }
    }

    fn handle_transfer_finish(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        transfer_id: MessageId,
        seq: u32,
    ) {
        let key = (peer, transfer_id);
        let Some(mut transfer_state) = state.inbound_transfers.remove(&key) else {
            return;
        };

        if seq < transfer_state.expected_seq {
            self.send_transfer_frame(
                state,
                peer,
                transfer_id,
                TransferFrame::Ack {
                    next_seq: transfer_state.expected_seq,
                },
                true,
            );
            state.inbound_transfers.insert(key, transfer_state);
            return;
        }

        if seq > transfer_state.expected_seq {
            let _ = transfer_state.chunk_tx.try_send(InboundStreamItem::Error(
                QlError::TransferProtocol { id: transfer_id },
            ));
            transfer_state.chunk_tx.close();
            self.send_transfer_frame(state, peer, transfer_id, TransferFrame::Cancel, true);
            return;
        }

        match transfer_state
            .chunk_tx
            .try_send(InboundStreamItem::Finished)
        {
            Ok(()) => {
                transfer_state.expected_seq = transfer_state.expected_seq.saturating_add(1);
                transfer_state.chunk_tx.close();
                self.send_transfer_frame(
                    state,
                    peer,
                    transfer_id,
                    TransferFrame::Ack {
                        next_seq: transfer_state.expected_seq,
                    },
                    true,
                );
            }
            Err(async_channel::TrySendError::Full(_)) => {
                state.inbound_transfers.insert(key, transfer_state);
            }
            Err(async_channel::TrySendError::Closed(_)) => {
                self.send_transfer_frame(state, peer, transfer_id, TransferFrame::Cancel, true);
            }
        }
    }

    fn handle_transfer_ack(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        transfer_id: MessageId,
        next_seq: u32,
    ) {
        let key = (peer, transfer_id);
        let Some(mut transfer_state) = state.outbound_transfers.remove(&key) else {
            return;
        };

        let matched = match transfer_state.awaiting.as_ref() {
            Some(OutboundAwaiting::Open { .. }) => next_seq == 1,
            Some(OutboundAwaiting::Chunk { seq, .. }) => next_seq == seq.saturating_add(1),
            Some(OutboundAwaiting::Finish { seq }) => next_seq == seq.saturating_add(1),
            Some(OutboundAwaiting::Cancel) | None => false,
        };
        if !matched {
            state.outbound_transfers.insert(key, transfer_state);
            return;
        }

        match transfer_state.awaiting.take() {
            Some(OutboundAwaiting::Open { .. }) => {
                transfer_state.stage = OutboundTransferStage::Streaming;
                state.outbound_transfers.insert(key, transfer_state);
            }
            Some(OutboundAwaiting::Chunk { seq, .. }) => {
                transfer_state.next_seq = seq.saturating_add(1);
                transfer_state.stage = OutboundTransferStage::Streaming;
                state.outbound_transfers.insert(key, transfer_state);
            }
            Some(OutboundAwaiting::Finish { .. }) => {
                transfer_state.chunk_rx.close();
            }
            Some(OutboundAwaiting::Cancel) | None => {
                state.outbound_transfers.insert(key, transfer_state);
            }
        }
    }

    fn handle_transfer_cancel(&self, state: &mut RuntimeState, peer: XID, transfer_id: MessageId) {
        let key = (peer, transfer_id);
        let mut acknowledged = false;

        if let Some(transfer_state) = state.outbound_transfers.remove(&key) {
            transfer_state.chunk_rx.close();
            acknowledged = true;
        }

        if let Some(transfer_state) = state.inbound_transfers.remove(&key) {
            let error = QlError::TransferCancelled { id: transfer_id };
            let _ = transfer_state
                .chunk_tx
                .try_send(InboundStreamItem::Error(error));
            transfer_state.chunk_tx.close();
            acknowledged = true;
        }

        if acknowledged {
            self.send_transfer_frame(state, peer, transfer_id, TransferFrame::CancelAck, true);
        }
    }

    fn handle_transfer_cancel_ack(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        transfer_id: MessageId,
    ) {
        let key = (peer, transfer_id);
        let Some(transfer_state) = state.outbound_transfers.remove(&key) else {
            return;
        };
        if !matches!(transfer_state.awaiting, Some(OutboundAwaiting::Cancel)) {
            state.outbound_transfers.insert(key, transfer_state);
            return;
        }

        transfer_state.chunk_rx.close();
    }

    fn drive_outbound_transfers(&self, state: &mut RuntimeState) {
        let keys: Vec<(XID, MessageId)> = state.outbound_transfers.keys().copied().collect();
        for (peer, transfer_id) in keys {
            self.drive_outbound_transfer(state, peer, transfer_id);
        }
    }

    fn drive_outbound_transfer(&self, state: &mut RuntimeState, peer: XID, transfer_id: MessageId) {
        let key = (peer, transfer_id);
        let Some(mut transfer_state) = state.outbound_transfers.remove(&key) else {
            return;
        };

        if transfer_state.awaiting.is_some() {
            state.outbound_transfers.insert(key, transfer_state);
            return;
        }

        match transfer_state.stage {
            OutboundTransferStage::Opening => {
                let Some(meta) = transfer_state.open_meta.take() else {
                    transfer_state.chunk_rx.close();
                    return;
                };
                let awaiting = OutboundAwaiting::Open {
                    request_id: transfer_state.request_id,
                    route_id: transfer_state.open_route_id,
                    meta,
                };
                if self.send_outbound_awaiting(state, &mut transfer_state, awaiting, 0) {
                    state.outbound_transfers.insert(key, transfer_state);
                }
            }
            OutboundTransferStage::Streaming => match transfer_state.chunk_rx.try_recv() {
                Ok(OutboundStreamInput::Chunk(data)) => {
                    let seq = transfer_state.next_seq;
                    let awaiting = OutboundAwaiting::Chunk { seq, data };
                    if self.send_outbound_awaiting(state, &mut transfer_state, awaiting, 0) {
                        state.outbound_transfers.insert(key, transfer_state);
                    }
                }
                Ok(OutboundStreamInput::Finish) => {
                    let seq = transfer_state.next_seq;
                    transfer_state.stage = OutboundTransferStage::Finishing;
                    let awaiting = OutboundAwaiting::Finish { seq };
                    if self.send_outbound_awaiting(state, &mut transfer_state, awaiting, 0) {
                        state.outbound_transfers.insert(key, transfer_state);
                    }
                }
                Err(async_channel::TryRecvError::Empty) => {
                    state.outbound_transfers.insert(key, transfer_state);
                }
                Err(async_channel::TryRecvError::Closed) => {
                    transfer_state.stage = OutboundTransferStage::Cancelling;
                    let awaiting = OutboundAwaiting::Cancel;
                    if self.send_outbound_awaiting(state, &mut transfer_state, awaiting, 0) {
                        state.outbound_transfers.insert(key, transfer_state);
                    }
                }
            },
            OutboundTransferStage::Finishing => {
                state.outbound_transfers.insert(key, transfer_state);
            }
            OutboundTransferStage::Cancelling => {
                let awaiting = OutboundAwaiting::Cancel;
                if self.send_outbound_awaiting(state, &mut transfer_state, awaiting, 0) {
                    state.outbound_transfers.insert(key, transfer_state);
                }
            }
        }
    }

    fn send_outbound_awaiting(
        &self,
        state: &mut RuntimeState,
        transfer_state: &mut OutboundTransferState,
        awaiting: OutboundAwaiting,
        attempt: u8,
    ) -> bool {
        let frame = match &awaiting {
            OutboundAwaiting::Open {
                request_id,
                route_id,
                meta,
            } => match route_id {
                Some(route_id) => TransferFrame::OpenRequest {
                    request_id: *request_id,
                    route_id: *route_id,
                    meta: meta.clone(),
                },
                None => TransferFrame::OpenResponse {
                    request_id: *request_id,
                    meta: meta.clone(),
                },
            },
            OutboundAwaiting::Chunk { seq, data } => TransferFrame::Chunk {
                seq: *seq,
                data: data.clone(),
            },
            OutboundAwaiting::Finish { seq } => TransferFrame::Finish { seq: *seq },
            OutboundAwaiting::Cancel => TransferFrame::Cancel,
        };

        let priority = matches!(awaiting, OutboundAwaiting::Cancel);
        if !self.send_transfer_frame(
            state,
            transfer_state.peer,
            transfer_state.transfer_id,
            frame,
            priority,
        ) {
            transfer_state.chunk_rx.close();
            return false;
        }

        transfer_state.awaiting = Some(awaiting);
        let at = Instant::now() + self.transfer_ack_timeout();
        match transfer_state.awaiting.as_ref() {
            Some(OutboundAwaiting::Open { .. }) => state.timeouts.push(Reverse(TimeoutEntry {
                at,
                kind: TimeoutKind::TransferAck {
                    peer: transfer_state.peer,
                    transfer_id: transfer_state.transfer_id,
                    next_seq: 1,
                    attempt,
                },
            })),
            Some(OutboundAwaiting::Chunk { seq, .. }) => {
                state.timeouts.push(Reverse(TimeoutEntry {
                    at,
                    kind: TimeoutKind::TransferAck {
                        peer: transfer_state.peer,
                        transfer_id: transfer_state.transfer_id,
                        next_seq: seq.saturating_add(1),
                        attempt,
                    },
                }))
            }
            Some(OutboundAwaiting::Finish { seq }) => state.timeouts.push(Reverse(TimeoutEntry {
                at,
                kind: TimeoutKind::TransferAck {
                    peer: transfer_state.peer,
                    transfer_id: transfer_state.transfer_id,
                    next_seq: seq.saturating_add(1),
                    attempt,
                },
            })),
            Some(OutboundAwaiting::Cancel) => state.timeouts.push(Reverse(TimeoutEntry {
                at,
                kind: TimeoutKind::TransferCancelAck {
                    peer: transfer_state.peer,
                    transfer_id: transfer_state.transfer_id,
                    attempt,
                },
            })),
            None => {}
        }

        true
    }

    fn send_transfer_frame(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        transfer_id: MessageId,
        frame: TransferFrame,
        priority: bool,
    ) -> bool {
        let Some(session_key) = state
            .peers
            .peer(peer)
            .and_then(|entry| entry.session.session_key())
            .cloned()
        else {
            return false;
        };

        let body = TransferBody {
            message_id: state.next_message_id(),
            valid_until: now_secs().saturating_add(self.config.message_expiration.as_secs()),
            transfer_id,
            frame,
        };
        let record = transfer::encrypt_transfer(
            QlHeader {
                sender: self.platform.xid(),
                recipient: peer,
            },
            &session_key,
            body,
        );
        let bytes = CBOR::from(record).to_cbor_data();
        self.enqueue_outbound_preencoded(
            state,
            peer,
            bytes,
            Instant::now() + self.config.message_expiration,
            priority,
        );
        true
    }

    fn transfer_ack_timeout(&self) -> std::time::Duration {
        if self.config.default_request_timeout.is_zero() {
            std::time::Duration::from_millis(200)
        } else {
            self.config.default_request_timeout
        }
    }

    fn handle_transfer_ack_timeout(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        transfer_id: MessageId,
        next_seq: u32,
        attempt: u8,
    ) {
        let key = (peer, transfer_id);
        let Some(mut transfer_state) = state.outbound_transfers.remove(&key) else {
            return;
        };

        let expected = match transfer_state.awaiting.as_ref() {
            Some(OutboundAwaiting::Open { .. }) => Some(1),
            Some(OutboundAwaiting::Chunk { seq, .. }) => Some(seq.saturating_add(1)),
            Some(OutboundAwaiting::Finish { seq }) => Some(seq.saturating_add(1)),
            _ => None,
        };
        if expected != Some(next_seq) {
            state.outbound_transfers.insert(key, transfer_state);
            return;
        }

        if attempt >= TRANSFER_RETRY_LIMIT {
            transfer_state.chunk_rx.close();
            return;
        }

        let Some(awaiting) = transfer_state.awaiting.take() else {
            state.outbound_transfers.insert(key, transfer_state);
            return;
        };
        if self.send_outbound_awaiting(state, &mut transfer_state, awaiting, attempt + 1) {
            state.outbound_transfers.insert(key, transfer_state);
        }
    }

    fn handle_transfer_cancel_ack_timeout(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        transfer_id: MessageId,
        attempt: u8,
    ) {
        let key = (peer, transfer_id);
        let Some(mut transfer_state) = state.outbound_transfers.remove(&key) else {
            return;
        };

        if !matches!(transfer_state.awaiting, Some(OutboundAwaiting::Cancel)) {
            state.outbound_transfers.insert(key, transfer_state);
            return;
        }

        if attempt >= TRANSFER_RETRY_LIMIT {
            transfer_state.chunk_rx.close();
            return;
        }

        transfer_state.awaiting = None;
        if self.send_outbound_awaiting(
            state,
            &mut transfer_state,
            OutboundAwaiting::Cancel,
            attempt + 1,
        ) {
            state.outbound_transfers.insert(key, transfer_state);
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
        self.enqueue_outbound(
            state,
            peer,
            OutboundPayload::PreEncoded(bytes),
            outbound_deadline,
            None,
        );
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
                    if let Some(entry) = state.pending_stream.remove(&id) {
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

    fn fail_pending_stream_for_peer(&self, state: &mut RuntimeState, peer: XID) {
        state
            .pending_stream
            .extract_if(|_id, entry| entry.recipient == peer)
            .for_each(|(_, entry)| {
                let _ = entry.tx.send(Err(QlError::SendFailed));
            });
    }

    fn abort_transfers_for_peer(&self, state: &mut RuntimeState, peer: XID, error: QlError) {
        state
            .outbound_transfers
            .extract_if(|(transfer_peer, _), _| *transfer_peer == peer)
            .for_each(|(_, transfer_state)| {
                transfer_state.chunk_rx.close();
            });

        state
            .inbound_transfers
            .extract_if(|(transfer_peer, _), _| *transfer_peer == peer)
            .for_each(|(_, transfer_state)| {
                let _ = transfer_state
                    .chunk_tx
                    .try_send(InboundStreamItem::Error(error.clone()));
                transfer_state.chunk_tx.close();
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
            return;
        }
        if let Some(entry) = state.pending_stream.remove(&id) {
            if entry.recipient == sender {
                let _ = entry.tx.send(Err(QlError::InvalidPayload));
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
            return;
        }
        if let Some(entry) = state.pending_stream.remove(&id) {
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
                self.enqueue_outbound(
                    state,
                    peer,
                    OutboundPayload::PreEncoded(bytes),
                    deadline,
                    None,
                );
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
        self.enqueue_outbound(
            state,
            peer,
            OutboundPayload::PreEncoded(bytes),
            deadline,
            None,
        );
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
            payload: OutboundPayload::PreEncoded(bytes),
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
        payload: OutboundPayload,
        deadline: Instant,
        message_id: Option<MessageId>,
    ) {
        let token = state.next_token();
        state.outbound.push_back(OutboundMessage {
            peer,
            token,
            message_id,
            payload,
        });
        state.timeouts.push(Reverse(TimeoutEntry {
            at: deadline,
            kind: TimeoutKind::Outbound { token },
        }));
    }

    fn enqueue_outbound_preencoded(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        bytes: Vec<u8>,
        deadline: Instant,
        priority: bool,
    ) {
        let token = state.next_token();
        let message = OutboundMessage {
            peer,
            token,
            message_id: None,
            payload: OutboundPayload::PreEncoded(bytes),
        };
        if priority {
            state.outbound.push_front(message);
        } else {
            state.outbound.push_back(message);
        }
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
                        if let Some(entry) = state.pending_stream.remove(&id) {
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
                    if let Some(entry) = state.pending_stream.remove(&id) {
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
                        self.fail_pending_stream_for_peer(state, peer);
                        self.abort_transfers_for_peer(state, peer, QlError::SendFailed);
                    }
                }
                TimeoutKind::TransferAck {
                    peer,
                    transfer_id,
                    next_seq,
                    attempt,
                } => {
                    self.handle_transfer_ack_timeout(state, peer, transfer_id, next_seq, attempt);
                }
                TimeoutKind::TransferCancelAck {
                    peer,
                    transfer_id,
                    attempt,
                } => {
                    self.handle_transfer_cancel_ack_timeout(state, peer, transfer_id, attempt);
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
            if let Some(entry) = state.pending_stream.remove(&id) {
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
            self.fail_pending_for_peer(state, peer);
            self.fail_pending_stream_for_peer(state, peer);
            self.abort_transfers_for_peer(state, peer, QlError::SendFailed);
        }
    }
}
