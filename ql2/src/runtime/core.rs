use std::{
    cmp::Reverse, collections::binary_heap::PeekMut, future::Future, task::Poll, time::Instant,
};

use bc_components::{MLDSAPublicKey, MLKEMPublicKey, SigningPublicKey, XID};
use dcbor::CBOR;
use futures_lite::future::poll_fn;

use crate::{
    platform::{QlPlatform, QlPlatformExt},
    runtime::{
        handle::{CallResponder, InboundByteStream, InboundCall},
        internal::{
            next_timeout_deadline, now_secs, peer_hello_wins, response_delivery, AwaitingPacket,
            CallPhase, CallRole, CallState, HelloAction, InFlightWrite, InboundStreamItem,
            InboundTerminal, InitiatorStage, KeepAliveState, LoopStep, OutboundCallStreamState,
            OutboundMessage, OutboundPayload, PendingChunk, RuntimeCommand, RuntimeState,
            TimeoutEntry, TimeoutKind,
        },
        replay_cache::{ReplayKey, ReplayNamespace},
        HandlerEvent, KeepAliveConfig, Runtime,
    },
    wire::{
        call::{
            self, AcceptStatus, CallBody, CallFrame, Direction, OpenFlags, RejectCode, ResetCode,
        },
        handshake::{self, HandshakeRecord},
        heartbeat::{self, HeartbeatBody},
        pair::{self, PairRequestRecord},
        unpair::{self, UnpairRecord},
        QlHeader, QlPayload, QlRecord,
    },
    CallId, MessageId, PacketId, QlError, RouteId,
};

const CALL_RETRY_LIMIT: u8 = 5;

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
            self.drive_calls(&mut state);
            if in_flight.is_none() {
                in_flight = self.start_next_write(&mut state);
            }
            match self.next_step(&state, in_flight.as_mut()).await {
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
                        self.handle_unpair_local(&mut state, peer);
                    }
                    RuntimeCommand::OpenCall {
                        recipient,
                        route_id,
                        request_head,
                        response_expected,
                        request_rx,
                        accepted,
                        start,
                        config,
                    } => {
                        self.handle_open_call(
                            &mut state,
                            recipient,
                            route_id,
                            request_head,
                            response_expected,
                            request_rx,
                            accepted,
                            start,
                            config,
                        );
                    }
                    RuntimeCommand::AcceptCall {
                        recipient,
                        call_id,
                        response_head,
                        response_rx,
                    } => {
                        self.handle_accept_call(
                            &mut state,
                            recipient,
                            call_id,
                            response_head,
                            response_rx,
                        );
                    }
                    RuntimeCommand::RejectCall {
                        recipient,
                        call_id,
                        code,
                    } => {
                        self.handle_reject_call(&mut state, recipient, call_id, code);
                    }
                    RuntimeCommand::PollCall { peer, call_id } => {
                        self.drive_call(&mut state, peer, call_id);
                    }
                    RuntimeCommand::AdvanceInboundCredit {
                        sender,
                        call_id,
                        dir,
                        amount,
                    } => {
                        self.handle_advance_inbound_credit(
                            &mut state, sender, call_id, dir, amount,
                        );
                    }
                    RuntimeCommand::ResetOutbound {
                        recipient,
                        call_id,
                        dir,
                        code,
                    } => {
                        self.handle_reset_outbound(&mut state, recipient, call_id, dir, code);
                    }
                    RuntimeCommand::ResetInbound {
                        sender,
                        call_id,
                        dir,
                        code,
                    } => {
                        self.handle_reset_inbound(&mut state, sender, call_id, dir, code);
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
                    call_id,
                    packet_id,
                    track_ack,
                    result,
                } => {
                    in_flight = None;
                    self.handle_write_done(
                        &mut state, peer, token, call_id, packet_id, track_ack, result,
                    );
                }
                LoopStep::Quit => break,
            }
        }
    }

    fn start_next_write<'a>(&'a self, state: &mut RuntimeState) -> Option<InFlightWrite<'a>> {
        while let Some(message) = state.outbound.pop_front() {
            let bytes = match message.payload {
                OutboundPayload::PreEncoded(bytes) => bytes,
                OutboundPayload::DeferredCall(body) => {
                    let Some(session_key) = state
                        .peers
                        .peer(message.peer)
                        .and_then(|entry| entry.session.session_key())
                    else {
                        if let Some(call_id) = message.call_id {
                            self.fail_call(state, message.peer, call_id, QlError::SendFailed);
                        }
                        continue;
                    };
                    let record = call::encrypt_call(
                        QlHeader {
                            sender: self.platform.xid(),
                            recipient: message.peer,
                        },
                        session_key,
                        body,
                    );
                    CBOR::from(record).to_cbor_data()
                }
            };
            return Some(InFlightWrite {
                peer: message.peer,
                token: message.token,
                call_id: message.call_id,
                packet_id: message.packet_id,
                track_ack: message.track_ack,
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
                        call_id: in_flight.call_id,
                        packet_id: in_flight.packet_id,
                        track_ack: in_flight.track_ack,
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
            if let crate::runtime::PeerSession::Disconnected = entry.session {
                self.platform.handle_peer_status(peer, &entry.session);
            }
        }
        self.persist_peers(state);
    }

    fn handle_connect(&self, state: &mut RuntimeState, peer: XID) {
        let encapsulation_key = match state.peers.peer(peer) {
            Some(entry) => match &entry.session {
                crate::runtime::PeerSession::Connected { .. }
                | crate::runtime::PeerSession::Initiator { .. }
                | crate::runtime::PeerSession::Responder { .. } => return,
                crate::runtime::PeerSession::Disconnected => entry.encapsulation_key.clone(),
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
            entry.session = crate::runtime::PeerSession::Initiator {
                handshake_token: token,
                hello: hello.clone(),
                session_key,
                deadline,
                stage: InitiatorStage::WaitingHelloReply,
            };
            self.platform.handle_peer_status(peer, &entry.session);
        }

        let record = QlRecord {
            header: QlHeader {
                sender: self.platform.xid(),
                recipient: peer,
            },
            payload: QlPayload::Handshake(HandshakeRecord::Hello(hello)),
        };
        self.enqueue_handshake_message(
            state,
            peer,
            token,
            deadline,
            CBOR::from(record).to_cbor_data(),
        );
    }

    fn handle_unpair_local(&self, state: &mut RuntimeState, peer: XID) {
        if state.peers.peer(peer).is_none() {
            return;
        }
        let record = unpair::build_unpair_record(
            &self.platform,
            QlHeader {
                sender: self.platform.xid(),
                recipient: peer,
            },
            crate::MessageId(state.next_packet_id().0),
            now_secs().saturating_add(self.config.packet_expiration.as_secs()),
        );
        self.unpair_peer(state, peer);
        self.enqueue_handshake_message(
            state,
            peer,
            state.next_token(),
            Instant::now() + self.config.packet_expiration,
            CBOR::from(record).to_cbor_data(),
        );
    }

    fn handle_open_call(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        route_id: RouteId,
        request_head: Vec<u8>,
        response_expected: bool,
        request_rx: async_channel::Receiver<crate::runtime::internal::OutboundStreamInput>,
        accepted: oneshot::Sender<Result<crate::runtime::AcceptedCallDelivery, QlError>>,
        start: oneshot::Sender<Result<CallId, QlError>>,
        config: crate::runtime::CallConfig,
    ) {
        let Some(entry) = state.peers.peer(recipient) else {
            let _ = start.send(Err(QlError::UnknownPeer(recipient)));
            return;
        };
        if !entry.session.is_connected() {
            let _ = start.send(Err(QlError::MissingSession(recipient)));
            return;
        }

        let timeout = config
            .open_timeout
            .unwrap_or(self.config.default_open_timeout);
        if timeout.is_zero() {
            let _ = start.send(Err(QlError::Timeout));
            return;
        }

        let call_id = state.next_call_id();
        let (response_tx, response_rx) = async_channel::bounded(1);
        let open_flags = OpenFlags::new(response_expected, false);
        let token = state.next_token();
        let mut outbound = OutboundCallStreamState::new(Direction::Request, request_rx, 0);
        outbound.queue.push_back(CallFrame::Open {
            call_id,
            route_id,
            flags: open_flags,
            request_head: request_head.clone(),
            response_max_offset: self.config.initial_credit,
        });
        let call = CallState {
            peer: recipient,
            call_id,
            route_id,
            role: CallRole::Initiator,
            phase: CallPhase::InitiatorOpening,
            open_flags,
            request_head,
            response_head: None,
            response_rx: Some(response_rx),
            accept_tx: Some(accepted),
            open_timeout_token: token,
            initial_remote_credit: 0,
            outbound: Some(outbound),
            inbound: crate::runtime::internal::InboundCallStreamState::new(
                Direction::Response,
                response_tx,
                self.config.initial_credit,
            ),
            accept_frame: None,
            last_activity: Instant::now(),
        };
        state.calls.insert((recipient, call_id), call);
        state.timeouts.push(Reverse(TimeoutEntry {
            at: Instant::now() + timeout,
            kind: TimeoutKind::CallOpen {
                peer: recipient,
                call_id,
                token,
            },
        }));
        let _ = start.send(Ok(call_id));
        self.drive_call(state, recipient, call_id);
    }

    fn handle_accept_call(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        call_id: CallId,
        response_head: Vec<u8>,
        response_rx: async_channel::Receiver<crate::runtime::internal::OutboundStreamInput>,
    ) {
        let key = (recipient, call_id);
        let Some(mut call) = state.calls.remove(&key) else {
            return;
        };
        if call.role != CallRole::Responder || call.phase != CallPhase::ResponderPending {
            state.calls.insert(key, call);
            return;
        }

        let mut outbound = OutboundCallStreamState::new(
            Direction::Response,
            response_rx,
            call.initial_remote_credit,
        );
        let frame = CallFrame::Accept {
            call_id,
            status: AcceptStatus::Accepted,
            response_head: response_head.clone(),
            request_max_offset: self.config.initial_credit,
        };
        outbound.queue.push_back(frame.clone());
        call.phase = CallPhase::ResponderAccepting;
        call.response_head = Some(response_head);
        call.accept_frame = Some(frame);
        call.inbound.max_offset = self.config.initial_credit;
        call.outbound = Some(outbound);
        call.last_activity = Instant::now();
        state.calls.insert(key, call);
        self.drive_call(state, recipient, call_id);
    }

    fn handle_reject_call(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        call_id: CallId,
        code: RejectCode,
    ) {
        let key = (recipient, call_id);
        let Some(mut call) = state.calls.remove(&key) else {
            return;
        };
        if call.role != CallRole::Responder || call.phase != CallPhase::ResponderPending {
            state.calls.insert(key, call);
            return;
        }
        let frame = CallFrame::Accept {
            call_id,
            status: AcceptStatus::Rejected(code),
            response_head: Vec::new(),
            request_max_offset: 0,
        };
        call.phase = CallPhase::ResponderAccepting;
        call.accept_frame = Some(frame.clone());
        let mut outbound = OutboundCallStreamState::new(
            Direction::Response,
            async_channel::bounded(1).1,
            call.initial_remote_credit,
        );
        outbound.closed = true;
        outbound.source_finished = true;
        outbound.queue.push_back(frame);
        call.outbound = Some(outbound);
        call.last_activity = Instant::now();
        state.calls.insert(key, call);
        self.drive_call(state, recipient, call_id);
    }

    fn handle_advance_inbound_credit(
        &self,
        state: &mut RuntimeState,
        sender: XID,
        call_id: CallId,
        dir: Direction,
        amount: u64,
    ) {
        let key = (sender, call_id);
        let Some(mut call) = state.calls.remove(&key) else {
            return;
        };
        if call.inbound.dir != dir || call.inbound.closed {
            state.calls.insert(key, call);
            return;
        }
        call.inbound.max_offset = call.inbound.max_offset.saturating_add(amount);
        self.flush_inbound_terminal(&mut call.inbound);
        self.queue_credit(&mut call, dir);
        call.last_activity = Instant::now();
        state.calls.insert(key, call);
        self.drive_call(state, sender, call_id);
    }

    fn handle_reset_outbound(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        call_id: CallId,
        dir: Direction,
        code: ResetCode,
    ) {
        let key = (recipient, call_id);
        let Some(mut call) = state.calls.remove(&key) else {
            return;
        };
        if call.local_outbound_dir() != dir {
            state.calls.insert(key, call);
            return;
        }
        if let Some(outbound) = call.outbound.as_mut() {
            if !outbound.closed {
                outbound.closed = true;
                outbound.source_finished = true;
                outbound.queue.clear();
                outbound.pending_chunk = None;
                outbound.queue.push_back(CallFrame::Reset {
                    call_id,
                    dir: match dir {
                        Direction::Request => call::ResetTarget::Request,
                        Direction::Response => call::ResetTarget::Response,
                    },
                    code,
                });
            }
        }
        call.last_activity = Instant::now();
        state.calls.insert(key, call);
        self.drive_call(state, recipient, call_id);
    }

    fn handle_reset_inbound(
        &self,
        state: &mut RuntimeState,
        sender: XID,
        call_id: CallId,
        dir: Direction,
        code: ResetCode,
    ) {
        let key = (sender, call_id);
        let Some(mut call) = state.calls.remove(&key) else {
            return;
        };
        if call.inbound.dir != dir || call.inbound.closed {
            state.calls.insert(key, call);
            return;
        }
        call.inbound.closed = true;
        call.inbound.pending_chunk = None;
        let _ = call
            .inbound
            .chunk_tx
            .try_send(InboundStreamItem::Error(QlError::CallReset {
                id: call_id,
                dir,
                code,
            }));
        call.inbound.chunk_tx.close();
        if let Some(outbound) = call.outbound.as_mut() {
            outbound.queue.push_back(CallFrame::Reset {
                call_id,
                dir: match dir {
                    Direction::Request => call::ResetTarget::Request,
                    Direction::Response => call::ResetTarget::Response,
                },
                code,
            });
        }
        call.last_activity = Instant::now();
        state.calls.insert(key, call);
        self.drive_call(state, sender, call_id);
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
            QlPayload::Handshake(message) => self.handle_handshake(state, header, message),
            QlPayload::Call(encrypted) => self.handle_call(state, header, encrypted),
            QlPayload::Heartbeat(encrypted) => self.handle_heartbeat(state, header, encrypted),
            QlPayload::Pair(request) => self.handle_pairing(state, header, request),
            QlPayload::Unpair(record) => self.handle_unpair(state, header, record),
        }
    }

    fn handle_handshake(
        &self,
        state: &mut RuntimeState,
        header: QlHeader,
        message: HandshakeRecord,
    ) {
        match message {
            HandshakeRecord::Hello(hello) => self.handle_hello(state, header, hello),
            HandshakeRecord::HelloReply(reply) => self.handle_hello_reply(state, header, reply),
            HandshakeRecord::Confirm(confirm) => self.handle_confirm(state, header, confirm),
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
        let replay_key = ReplayKey::new(
            peer,
            ReplayNamespace::Peer,
            crate::MessageId(record.message_id.0),
        );
        if state
            .replay_cache
            .check_and_store_valid_until(replay_key, record.valid_until)
        {
            return;
        }
        self.unpair_peer(state, peer);
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
                crate::runtime::PeerSession::Connected {
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

    fn handle_call(
        &self,
        state: &mut RuntimeState,
        header: QlHeader,
        encrypted: bc_components::EncryptedMessage,
    ) {
        let peer = header.sender;
        let session_key = match state.peers.peer(peer) {
            Some(entry) => match &entry.session {
                crate::runtime::PeerSession::Connected { session_key, .. } => session_key.clone(),
                _ => return,
            },
            None => return,
        };
        let body = match call::decrypt_call(&header, &encrypted, &session_key) {
            Ok(body) => body,
            Err(_) => return,
        };

        if let Some(ack) = body.packet_ack {
            self.process_packet_ack(state, peer, ack.packet_id);
        }

        let Some(frame) = body.frame else {
            return;
        };

        let replay_key =
            ReplayKey::new(peer, ReplayNamespace::Transfer, MessageId(body.packet_id.0));
        if state
            .replay_cache
            .check_and_store_valid_until(replay_key, body.valid_until)
        {
            return;
        }

        self.record_activity(state, peer);
        self.record_call_activity(state, peer, frame.call_id());
        self.send_packet_ack(state, peer, body.packet_id);

        match frame {
            CallFrame::Open {
                call_id,
                route_id,
                flags,
                request_head,
                response_max_offset,
            } => self.handle_call_open(
                state,
                peer,
                call_id,
                route_id,
                flags,
                request_head,
                response_max_offset,
            ),
            CallFrame::Accept {
                call_id,
                status,
                response_head,
                request_max_offset,
            } => self.handle_call_accept(
                state,
                peer,
                call_id,
                status,
                response_head,
                request_max_offset,
            ),
            CallFrame::Data {
                call_id,
                dir,
                offset,
                bytes,
            } => self.handle_call_data(state, peer, call_id, dir, offset, bytes),
            CallFrame::Credit {
                call_id,
                dir,
                recv_offset,
                max_offset,
            } => self.handle_call_credit(state, peer, call_id, dir, recv_offset, max_offset),
            CallFrame::Finish { call_id, dir } => {
                self.handle_call_finish(state, peer, call_id, dir)
            }
            CallFrame::Reset { call_id, dir, code } => {
                self.handle_call_reset(state, peer, call_id, dir, code)
            }
        }
    }

    fn handle_call_open(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        call_id: CallId,
        route_id: RouteId,
        flags: OpenFlags,
        request_head: Vec<u8>,
        response_max_offset: u64,
    ) {
        let key = (peer, call_id);
        if let Some(call) = state.calls.get(&key) {
            if call.role == CallRole::Responder
                && call.route_id == route_id
                && call.open_flags == flags
                && call.request_head == request_head
                && call.initial_remote_credit == response_max_offset
            {
                return;
            }
            self.send_ephemeral_reset(
                state,
                peer,
                call_id,
                call::ResetTarget::Both,
                ResetCode::Protocol,
            );
            return;
        }

        let (request_tx, request_rx) = async_channel::bounded(1);
        let responder = CallResponder::new(call_id, peer, self.tx.upgrade().expect("runtime tx"));
        let mut inbound = crate::runtime::internal::InboundCallStreamState::new(
            Direction::Request,
            request_tx,
            0,
        );
        if flags.request_finished() {
            inbound.terminal = Some(InboundTerminal::Finished);
            self.flush_inbound_terminal(&mut inbound);
        }

        let call = CallState {
            peer,
            call_id,
            route_id,
            role: CallRole::Responder,
            phase: CallPhase::ResponderPending,
            open_flags: flags,
            request_head: request_head.clone(),
            response_head: None,
            response_rx: None,
            accept_tx: None,
            open_timeout_token: crate::runtime::Token(0),
            initial_remote_credit: response_max_offset,
            outbound: None,
            inbound,
            accept_frame: None,
            last_activity: Instant::now(),
        };
        state.calls.insert(key, call);
        self.platform
            .handle_inbound(HandlerEvent::Call(InboundCall {
                sender: peer,
                recipient: self.platform.xid(),
                route_id,
                call_id,
                request_head,
                response_expected: flags.response_expected(),
                request: InboundByteStream::new(
                    peer,
                    call_id,
                    Direction::Request,
                    request_rx,
                    self.tx.upgrade().expect("runtime tx"),
                ),
                respond_to: responder,
            }));
    }

    fn handle_call_accept(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        call_id: CallId,
        status: AcceptStatus,
        response_head: Vec<u8>,
        request_max_offset: u64,
    ) {
        let key = (peer, call_id);
        let Some(mut call) = state.calls.remove(&key) else {
            return;
        };
        if call.role != CallRole::Initiator {
            self.send_ephemeral_reset(
                state,
                peer,
                call_id,
                call::ResetTarget::Both,
                ResetCode::Protocol,
            );
            state.calls.insert(key, call);
            return;
        }
        if let Some(existing) = &call.accept_frame {
            if *existing
                == (CallFrame::Accept {
                    call_id,
                    status: status.clone(),
                    response_head: response_head.clone(),
                    request_max_offset,
                })
            {
                state.calls.insert(key, call);
                return;
            }
            self.fail_call(state, peer, call_id, QlError::CallProtocol { id: call_id });
            return;
        }

        if let Some(outbound) = call.outbound.as_mut() {
            if matches!(
                outbound.awaiting.as_ref().map(|awaiting| &awaiting.frame),
                Some(CallFrame::Open { .. })
            ) {
                outbound.awaiting = None;
            }
        }

        call.accept_frame = Some(CallFrame::Accept {
            call_id,
            status: status.clone(),
            response_head: response_head.clone(),
            request_max_offset,
        });

        match status {
            AcceptStatus::Accepted => {
                call.phase = CallPhase::Open;
                call.response_head = Some(response_head);
                if let Some(outbound) = call.outbound.as_mut() {
                    outbound.remote_max_offset = request_max_offset;
                    outbound.data_enabled = true;
                }
                if let Some(tx) = call.accept_tx.take() {
                    let delivery =
                        response_delivery(&mut call, self.tx.upgrade().expect("runtime tx"));
                    let _ = tx.send(delivery.ok_or(QlError::Cancelled));
                }
            }
            AcceptStatus::Rejected(code) => {
                call.phase = CallPhase::Rejected;
                if let Some(outbound) = call.outbound.as_mut() {
                    outbound.closed = true;
                    outbound.queue.clear();
                    outbound.pending_chunk = None;
                    outbound.awaiting = None;
                    outbound.chunk_rx.close();
                }
                if let Some(tx) = call.accept_tx.take() {
                    let _ = tx.send(Err(QlError::CallRejected { id: call_id, code }));
                }
                call.inbound.closed = true;
                call.inbound.chunk_tx.close();
            }
        }

        call.last_activity = Instant::now();
        state.calls.insert(key, call);
        self.drive_call(state, peer, call_id);
    }

    fn handle_call_data(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        call_id: CallId,
        dir: Direction,
        offset: u64,
        bytes: Vec<u8>,
    ) {
        let key = (peer, call_id);
        let Some(mut call) = state.calls.remove(&key) else {
            return;
        };
        self.note_accept_seen_from_remote(&mut call);
        if call.inbound.dir != dir || call.inbound.closed {
            self.fail_call(state, peer, call_id, QlError::CallProtocol { id: call_id });
            return;
        }
        if offset < call.inbound.next_offset {
            self.queue_credit(&mut call, dir);
            state.calls.insert(key, call);
            self.drive_call(state, peer, call_id);
            return;
        }
        let end = offset.saturating_add(bytes.len() as u64);
        if offset != call.inbound.next_offset || end > call.inbound.max_offset {
            self.queue_local_reset(&mut call, call::ResetTarget::Both, ResetCode::Protocol);
            state.calls.insert(key, call);
            self.drive_call(state, peer, call_id);
            return;
        }

        call.inbound.next_offset = end;
        if call.inbound.pending_chunk.is_some() {
            self.queue_local_reset(&mut call, call::ResetTarget::Both, ResetCode::Protocol);
            state.calls.insert(key, call);
            self.drive_call(state, peer, call_id);
            return;
        }

        match call
            .inbound
            .chunk_tx
            .try_send(InboundStreamItem::Chunk(bytes))
        {
            Ok(()) => {}
            Err(async_channel::TrySendError::Full(InboundStreamItem::Chunk(chunk))) => {
                call.inbound.pending_chunk = Some(chunk);
            }
            Err(async_channel::TrySendError::Closed(_)) => {
                self.queue_local_reset(&mut call, call::ResetTarget::Both, ResetCode::Cancelled);
            }
            Err(async_channel::TrySendError::Full(_)) => unreachable!(),
        }
        self.queue_credit(&mut call, dir);
        call.last_activity = Instant::now();
        state.calls.insert(key, call);
        self.drive_call(state, peer, call_id);
    }

    fn handle_call_credit(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        call_id: CallId,
        dir: Direction,
        recv_offset: u64,
        max_offset: u64,
    ) {
        let key = (peer, call_id);
        let Some(mut call) = state.calls.remove(&key) else {
            return;
        };
        self.note_accept_seen_from_remote(&mut call);
        let Some(outbound) = call.outbound.as_mut() else {
            state.calls.insert(key, call);
            return;
        };
        if outbound.dir != dir
            || recv_offset < outbound.remote_recv_offset
            || recv_offset > outbound.next_offset
            || max_offset < recv_offset
        {
            self.queue_local_reset(&mut call, call::ResetTarget::Both, ResetCode::Protocol);
            state.calls.insert(key, call);
            self.drive_call(state, peer, call_id);
            return;
        }
        outbound.remote_recv_offset = recv_offset;
        outbound.remote_max_offset = outbound.remote_max_offset.max(max_offset);
        call.last_activity = Instant::now();
        state.calls.insert(key, call);
        self.drive_call(state, peer, call_id);
    }

    fn handle_call_finish(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        call_id: CallId,
        dir: Direction,
    ) {
        let key = (peer, call_id);
        let Some(mut call) = state.calls.remove(&key) else {
            return;
        };
        self.note_accept_seen_from_remote(&mut call);
        if call.inbound.dir != dir || call.inbound.closed {
            state.calls.insert(key, call);
            return;
        }
        call.inbound.terminal = Some(InboundTerminal::Finished);
        self.flush_inbound_terminal(&mut call.inbound);
        call.last_activity = Instant::now();
        state.calls.insert(key, call);
    }

    fn handle_call_reset(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        call_id: CallId,
        dir: call::ResetTarget,
        code: ResetCode,
    ) {
        let key = (peer, call_id);
        let Some(mut call) = state.calls.remove(&key) else {
            return;
        };
        self.note_accept_seen_from_remote(&mut call);
        if matches!(dir, call::ResetTarget::Request | call::ResetTarget::Both)
            && call.inbound.dir == Direction::Request
        {
            call.inbound.pending_chunk = None;
            call.inbound.terminal = Some(InboundTerminal::Error(QlError::CallReset {
                id: call_id,
                dir: Direction::Request,
                code,
            }));
            self.flush_inbound_terminal(&mut call.inbound);
        }
        if matches!(dir, call::ResetTarget::Response | call::ResetTarget::Both)
            && call.inbound.dir == Direction::Response
        {
            call.inbound.pending_chunk = None;
            call.inbound.terminal = Some(InboundTerminal::Error(QlError::CallReset {
                id: call_id,
                dir: Direction::Response,
                code,
            }));
            self.flush_inbound_terminal(&mut call.inbound);
        }
        if let Some(outbound) = call.outbound.as_mut() {
            let affects_outbound = match (dir, outbound.dir) {
                (call::ResetTarget::Request, Direction::Request)
                | (call::ResetTarget::Response, Direction::Response)
                | (call::ResetTarget::Both, _) => true,
                _ => false,
            };
            if affects_outbound {
                outbound.queue.clear();
                outbound.pending_chunk = None;
                outbound.awaiting = None;
                outbound.closed = true;
                outbound.chunk_rx.close();
            }
        }
        if let Some(tx) = call.accept_tx.take() {
            let _ = tx.send(Err(QlError::CallReset {
                id: call_id,
                dir: call.inbound.dir,
                code,
            }));
        }
        call.phase = CallPhase::Closed;
        call.last_activity = Instant::now();
        state.calls.insert(key, call);
    }

    fn process_packet_ack(&self, state: &mut RuntimeState, peer: XID, packet_id: PacketId) {
        let key = state.calls.iter().find_map(|(key, call)| {
            (key.0 == peer
                && call
                    .outbound
                    .as_ref()
                    .and_then(|outbound| outbound.awaiting.as_ref())
                    .is_some_and(|awaiting| awaiting.packet_id == packet_id))
            .then_some(*key)
        });
        let Some(key) = key else {
            return;
        };
        let Some(mut call) = state.calls.remove(&key) else {
            return;
        };
        let Some(outbound) = call.outbound.as_mut() else {
            state.calls.insert(key, call);
            return;
        };
        let Some(awaiting) = outbound.awaiting.take() else {
            state.calls.insert(key, call);
            return;
        };

        match awaiting.frame {
            CallFrame::Open { .. } => {
                if call.phase == CallPhase::InitiatorOpening {
                    call.phase = CallPhase::InitiatorWaitingAccept;
                }
            }
            CallFrame::Accept {
                status: AcceptStatus::Accepted,
                ..
            } => {
                if call.phase == CallPhase::ResponderAccepting {
                    call.phase = CallPhase::Open;
                    outbound.data_enabled = true;
                }
            }
            CallFrame::Accept {
                status: AcceptStatus::Rejected(_),
                ..
            } => {
                call.phase = CallPhase::Rejected;
                outbound.closed = true;
                outbound.chunk_rx.close();
            }
            CallFrame::Finish { .. } => {
                outbound.chunk_rx.close();
            }
            CallFrame::Reset { dir, .. } => {
                let affects_outbound = match (dir, outbound.dir) {
                    (call::ResetTarget::Request, Direction::Request)
                    | (call::ResetTarget::Response, Direction::Response)
                    | (call::ResetTarget::Both, _) => true,
                    _ => false,
                };
                if affects_outbound {
                    outbound.chunk_rx.close();
                }
            }
            CallFrame::Data { .. } | CallFrame::Credit { .. } => {}
        }

        state.calls.insert(key, call);
        self.drive_call(state, key.0, key.1);
    }

    fn drive_calls(&self, state: &mut RuntimeState) {
        let keys: Vec<_> = state.calls.keys().copied().collect();
        for (peer, call_id) in keys {
            self.drive_call(state, peer, call_id);
        }
    }

    fn drive_call(&self, state: &mut RuntimeState, peer: XID, call_id: CallId) {
        let key = (peer, call_id);
        let Some(mut call) = state.calls.remove(&key) else {
            return;
        };
        let Some(_) = call.outbound.as_ref() else {
            state.calls.insert(key, call);
            return;
        };

        let mut next_frame = None;
        {
            let outbound = call.outbound.as_mut().unwrap();
            if outbound.awaiting.is_none() {
                if let Some(frame) = outbound.queue.pop_front() {
                    next_frame = Some(frame);
                } else if outbound.data_enabled && !outbound.closed {
                    if outbound.pending_chunk.is_none() && !outbound.source_finished {
                        while let Ok(input) = outbound.chunk_rx.try_recv() {
                            match input {
                                crate::runtime::internal::OutboundStreamInput::Chunk(chunk) => {
                                    if chunk.is_empty() {
                                        continue;
                                    }
                                    outbound.pending_chunk = Some(PendingChunk {
                                        bytes: chunk,
                                        sent: 0,
                                    });
                                    break;
                                }
                                crate::runtime::internal::OutboundStreamInput::Finish => {
                                    outbound.source_finished = true;
                                    break;
                                }
                            }
                        }
                    }

                    if let Some(chunk) = outbound.pending_chunk.as_mut() {
                        let remaining_credit = outbound
                            .remote_max_offset
                            .saturating_sub(outbound.next_offset)
                            as usize;
                        if remaining_credit > 0 {
                            let remaining = chunk.bytes.len().saturating_sub(chunk.sent);
                            let len = remaining
                                .min(self.config.max_payload_bytes)
                                .min(remaining_credit);
                            if len > 0 {
                                let offset = outbound.next_offset;
                                let dir = outbound.dir;
                                let bytes = chunk.bytes[chunk.sent..chunk.sent + len].to_vec();
                                chunk.sent += len;
                                outbound.next_offset =
                                    outbound.next_offset.saturating_add(len as u64);
                                if chunk.sent == chunk.bytes.len() {
                                    outbound.pending_chunk = None;
                                }
                                next_frame = Some(CallFrame::Data {
                                    call_id,
                                    dir,
                                    offset,
                                    bytes,
                                });
                            }
                        }
                    } else if outbound.source_finished {
                        outbound.closed = true;
                        next_frame = Some(CallFrame::Finish {
                            call_id,
                            dir: outbound.dir,
                        });
                    }
                }
            }
        }

        if let Some(frame) = next_frame {
            self.send_tracked_frame(state, &mut call, frame, 0);
        }

        state.calls.insert(key, call);
    }

    fn send_tracked_frame(
        &self,
        state: &mut RuntimeState,
        call: &mut CallState,
        frame: CallFrame,
        attempt: u8,
    ) {
        let packet_id = state.next_packet_id();
        let Some(outbound) = call.outbound.as_mut() else {
            return;
        };
        outbound.awaiting = Some(AwaitingPacket {
            packet_id,
            frame: frame.clone(),
            attempt,
        });
        let valid_until = now_secs().saturating_add(self.config.packet_expiration.as_secs());
        self.enqueue_call_body(
            state,
            call.peer,
            Some(call.call_id),
            Some(packet_id),
            true,
            false,
            CallBody {
                packet_id,
                valid_until,
                packet_ack: None,
                frame: Some(frame),
            },
        );
    }

    fn queue_credit(&self, call: &mut CallState, dir: Direction) {
        if let Some(outbound) = call.outbound.as_mut() {
            outbound.queue.push_back(CallFrame::Credit {
                call_id: call.call_id,
                dir,
                recv_offset: call.inbound.next_offset,
                max_offset: call.inbound.max_offset,
            });
        }
    }

    fn queue_local_reset(&self, call: &mut CallState, dir: call::ResetTarget, code: ResetCode) {
        if let Some(outbound) = call.outbound.as_mut() {
            outbound.queue.clear();
            outbound.pending_chunk = None;
            outbound.queue.push_back(CallFrame::Reset {
                call_id: call.call_id,
                dir,
                code,
            });
            outbound.closed = true;
        }
        call.inbound.closed = true;
        call.inbound.pending_chunk = None;
        call.inbound.terminal = Some(InboundTerminal::Error(QlError::CallProtocol {
            id: call.call_id,
        }));
        self.flush_inbound_terminal(&mut call.inbound);
    }

    fn note_accept_seen_from_remote(&self, call: &mut CallState) {
        if call.role != CallRole::Responder || call.phase != CallPhase::ResponderAccepting {
            return;
        }
        let Some(outbound) = call.outbound.as_mut() else {
            return;
        };
        if matches!(
            outbound.awaiting.as_ref().map(|awaiting| &awaiting.frame),
            Some(CallFrame::Accept { .. })
        ) {
            outbound.awaiting = None;
            if matches!(
                call.accept_frame,
                Some(CallFrame::Accept {
                    status: AcceptStatus::Accepted,
                    ..
                })
            ) {
                call.phase = CallPhase::Open;
                outbound.data_enabled = true;
            } else {
                call.phase = CallPhase::Rejected;
                outbound.closed = true;
            }
        }
    }

    fn flush_inbound_terminal(
        &self,
        inbound: &mut crate::runtime::internal::InboundCallStreamState,
    ) {
        if let Some(chunk) = inbound.pending_chunk.take() {
            match inbound.chunk_tx.try_send(InboundStreamItem::Chunk(chunk)) {
                Ok(()) => {}
                Err(async_channel::TrySendError::Full(InboundStreamItem::Chunk(chunk))) => {
                    inbound.pending_chunk = Some(chunk);
                    return;
                }
                Err(async_channel::TrySendError::Closed(_)) => {
                    inbound.closed = true;
                    return;
                }
                Err(async_channel::TrySendError::Full(_)) => unreachable!(),
            }
        }

        let Some(terminal) = inbound.terminal.take() else {
            return;
        };
        match terminal {
            InboundTerminal::Finished => {
                match inbound.chunk_tx.try_send(InboundStreamItem::Finished) {
                    Ok(()) => {
                        inbound.closed = true;
                        inbound.chunk_tx.close();
                    }
                    Err(async_channel::TrySendError::Full(_)) => {
                        inbound.terminal = Some(InboundTerminal::Finished);
                    }
                    Err(async_channel::TrySendError::Closed(_)) => {
                        inbound.closed = true;
                    }
                }
            }
            InboundTerminal::Error(error) => match inbound
                .chunk_tx
                .try_send(InboundStreamItem::Error(error.clone()))
            {
                Ok(()) => {
                    inbound.closed = true;
                    inbound.chunk_tx.close();
                }
                Err(async_channel::TrySendError::Full(_)) => {
                    inbound.terminal = Some(InboundTerminal::Error(error));
                }
                Err(async_channel::TrySendError::Closed(_)) => {
                    inbound.closed = true;
                }
            },
        }
    }

    fn send_packet_ack(&self, state: &mut RuntimeState, peer: XID, acked_packet: PacketId) {
        let packet_id = state.next_packet_id();
        let valid_until = now_secs().saturating_add(self.config.packet_expiration.as_secs());
        self.enqueue_call_body(
            state,
            peer,
            None,
            None,
            false,
            true,
            CallBody {
                packet_id,
                valid_until,
                packet_ack: Some(call::PacketAck {
                    packet_id: acked_packet,
                }),
                frame: None,
            },
        );
    }

    fn send_ephemeral_reset(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        call_id: CallId,
        dir: call::ResetTarget,
        code: ResetCode,
    ) {
        let packet_id = state.next_packet_id();
        let valid_until = now_secs().saturating_add(self.config.packet_expiration.as_secs());
        self.enqueue_call_body(
            state,
            peer,
            None,
            None,
            false,
            true,
            CallBody {
                packet_id,
                valid_until,
                packet_ack: None,
                frame: Some(CallFrame::Reset { call_id, dir, code }),
            },
        );
    }

    fn enqueue_handshake_message(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        token: crate::runtime::Token,
        deadline: Instant,
        bytes: Vec<u8>,
    ) {
        state.outbound.push_back(OutboundMessage {
            peer,
            token,
            call_id: None,
            packet_id: None,
            track_ack: false,
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

    fn enqueue_call_body(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        call_id: Option<CallId>,
        packet_id: Option<PacketId>,
        track_ack: bool,
        priority: bool,
        body: CallBody,
    ) {
        let token = state.next_token();
        let message = OutboundMessage {
            peer,
            token,
            call_id,
            packet_id,
            track_ack,
            payload: OutboundPayload::DeferredCall(body),
        };
        if priority {
            state.outbound.push_front(message);
        } else {
            state.outbound.push_back(message);
        }
        state.timeouts.push(Reverse(TimeoutEntry {
            at: Instant::now() + self.config.packet_expiration,
            kind: TimeoutKind::Outbound { token },
        }));
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
                crate::runtime::PeerSession::Initiator {
                    hello: local_hello, ..
                } => {
                    if peer_hello_wins(local_hello, self.platform.xid(), &hello, peer) {
                        HelloAction::StartResponder
                    } else {
                        HelloAction::Ignore
                    }
                }
                crate::runtime::PeerSession::Responder {
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
                crate::runtime::PeerSession::Disconnected
                | crate::runtime::PeerSession::Connected { .. } => HelloAction::StartResponder,
            },
            None => return,
        };

        match action {
            HelloAction::StartResponder => self.start_responder_handshake(state, peer, hello),
            HelloAction::ResendReply { reply, deadline } => {
                let record = QlRecord {
                    header: QlHeader {
                        sender: self.platform.xid(),
                        recipient: peer,
                    },
                    payload: QlPayload::Handshake(HandshakeRecord::HelloReply(reply)),
                };
                self.enqueue_handshake_message(
                    state,
                    peer,
                    state.next_token(),
                    deadline,
                    CBOR::from(record).to_cbor_data(),
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
                crate::runtime::PeerSession::Initiator {
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
                    entry.session = crate::runtime::PeerSession::Connected {
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
                    entry.session = crate::runtime::PeerSession::Disconnected;
                    self.platform.handle_peer_status(peer, &entry.session);
                }
                return;
            }
        };

        let record = QlRecord {
            header: QlHeader {
                sender: self.platform.xid(),
                recipient: peer,
            },
            payload: QlPayload::Handshake(HandshakeRecord::Confirm(confirm)),
        };
        self.enqueue_handshake_message(
            state,
            peer,
            state.next_token(),
            Instant::now() + self.config.handshake_timeout,
            CBOR::from(record).to_cbor_data(),
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
                crate::runtime::PeerSession::Responder {
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
                    entry.session = crate::runtime::PeerSession::Connected {
                        session_key,
                        keepalive: KeepAliveState::new(),
                    };
                    self.platform.handle_peer_status(peer, &entry.session);
                }
                self.record_activity(state, peer);
            }
            Err(_) => {
                if let Some(entry) = state.peers.peer_mut(peer) {
                    entry.session = crate::runtime::PeerSession::Disconnected;
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
                    entry.session = crate::runtime::PeerSession::Disconnected;
                    self.platform.handle_peer_status(peer, &entry.session);
                }
                return;
            }
        };

        let deadline = Instant::now() + self.config.handshake_timeout;
        let token = state.next_token();
        if let Some(entry) = state.peers.peer_mut(peer) {
            entry.session = crate::runtime::PeerSession::Responder {
                handshake_token: token,
                hello: hello.clone(),
                reply: reply.clone(),
                secrets,
                deadline,
            };
            self.platform.handle_peer_status(peer, &entry.session);
        }

        let record = QlRecord {
            header: QlHeader {
                sender: self.platform.xid(),
                recipient: peer,
            },
            payload: QlPayload::Handshake(HandshakeRecord::HelloReply(reply)),
        };
        self.enqueue_handshake_message(
            state,
            peer,
            token,
            deadline,
            CBOR::from(record).to_cbor_data(),
        );
    }

    fn send_heartbeat_message(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        session_key: bc_components::SymmetricKey,
    ) {
        let message = heartbeat::encrypt_heartbeat(
            QlHeader {
                sender: self.platform.xid(),
                recipient: peer,
            },
            &session_key,
            HeartbeatBody {
                message_id: MessageId(state.next_packet_id().0),
                valid_until: now_secs().saturating_add(self.config.packet_expiration.as_secs()),
            },
        );
        self.enqueue_handshake_message(
            state,
            peer,
            state.next_token(),
            Instant::now() + self.config.packet_expiration,
            CBOR::from(message).to_cbor_data(),
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
        let crate::runtime::PeerSession::Connected { keepalive, .. } = &mut entry.session else {
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

    fn record_call_activity(&self, state: &mut RuntimeState, peer: XID, call_id: CallId) {
        if let Some(call) = state.calls.get_mut(&(peer, call_id)) {
            call.last_activity = Instant::now();
        }
    }

    fn persist_peers(&self, state: &RuntimeState) {
        self.platform.persist_peers(state.peers.all());
    }

    fn drop_outbound_for_peer(&self, state: &mut RuntimeState, peer: XID) {
        let call_ids: Vec<_> = state
            .outbound
            .iter()
            .filter(|message| message.peer == peer)
            .filter_map(|message| message.call_id)
            .collect();
        state.outbound.retain(|message| message.peer != peer);
        for call_id in call_ids {
            self.fail_call(state, peer, call_id, QlError::SendFailed);
        }
    }

    fn abort_calls_for_peer(&self, state: &mut RuntimeState, peer: XID, error: QlError) {
        let keys: Vec<_> = state
            .calls
            .keys()
            .copied()
            .filter(|(call_peer, _)| *call_peer == peer)
            .collect();
        for (_, call_id) in keys {
            self.fail_call(state, peer, call_id, error.clone());
        }
    }

    fn fail_call(&self, state: &mut RuntimeState, peer: XID, call_id: CallId, error: QlError) {
        let Some(mut call) = state.calls.remove(&(peer, call_id)) else {
            return;
        };
        if let Some(tx) = call.accept_tx.take() {
            let _ = tx.send(Err(error.clone()));
        }
        if let Some(outbound) = call.outbound.as_mut() {
            outbound.queue.clear();
            outbound.pending_chunk = None;
            outbound.awaiting = None;
            outbound.closed = true;
            outbound.chunk_rx.close();
        }
        call.inbound.pending_chunk = None;
        let _ = call
            .inbound
            .chunk_tx
            .try_send(InboundStreamItem::Error(error));
        call.inbound.chunk_tx.close();
    }

    fn unpair_peer(&self, state: &mut RuntimeState, peer: XID) {
        if state.peers.remove_peer(peer).is_none() {
            return;
        }
        self.drop_outbound_for_peer(state, peer);
        self.abort_calls_for_peer(state, peer, QlError::SendFailed);
        state.replay_cache.clear_peer(peer);
        self.platform
            .handle_peer_status(peer, &crate::runtime::PeerSession::Disconnected);
        self.persist_peers(state);
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
                    let mut timed_out_call = None;
                    state.outbound.retain(|message| {
                        if message.token == token {
                            timed_out_call = message.call_id.map(|call_id| (message.peer, call_id));
                            false
                        } else {
                            true
                        }
                    });
                    if let Some((peer, call_id)) = timed_out_call {
                        self.fail_call(state, peer, call_id, QlError::SendFailed);
                    }
                }
                TimeoutKind::Handshake { peer, token } => {
                    let Some(entry) = state.peers.peer(peer) else {
                        continue;
                    };
                    let should_disconnect = match &entry.session {
                        crate::runtime::PeerSession::Initiator {
                            handshake_token, ..
                        }
                        | crate::runtime::PeerSession::Responder {
                            handshake_token, ..
                        } => *handshake_token == token,
                        _ => false,
                    };
                    if should_disconnect {
                        if let Some(entry) = state.peers.peer_mut(peer) {
                            entry.session = crate::runtime::PeerSession::Disconnected;
                            self.platform.handle_peer_status(peer, &entry.session);
                        }
                        self.drop_outbound_for_peer(state, peer);
                        self.abort_calls_for_peer(state, peer, QlError::SendFailed);
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
                        let crate::runtime::PeerSession::Connected {
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
                        if let crate::runtime::PeerSession::Connected { keepalive, .. } =
                            &mut entry.session
                        {
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
                        crate::runtime::PeerSession::Connected { keepalive, .. } => {
                            keepalive.token == token && keepalive.pending
                        }
                        _ => false,
                    };
                    if should_disconnect {
                        if let Some(entry) = state.peers.peer_mut(peer) {
                            entry.session = crate::runtime::PeerSession::Disconnected;
                            self.platform.handle_peer_status(peer, &entry.session);
                        }
                        self.drop_outbound_for_peer(state, peer);
                        self.abort_calls_for_peer(state, peer, QlError::SendFailed);
                    }
                }
                TimeoutKind::CallOpen {
                    peer,
                    call_id,
                    token,
                } => {
                    let should_fail = state.calls.get(&(peer, call_id)).is_some_and(|call| {
                        call.open_timeout_token == token
                            && (call.phase == CallPhase::InitiatorOpening
                                || call.phase == CallPhase::InitiatorWaitingAccept)
                    });
                    if should_fail {
                        self.fail_call(state, peer, call_id, QlError::Timeout);
                    }
                }
                TimeoutKind::CallPacket {
                    peer,
                    call_id,
                    packet_id,
                    attempt,
                } => {
                    let key = (peer, call_id);
                    let Some(mut call) = state.calls.remove(&key) else {
                        continue;
                    };
                    let should_retry = call
                        .outbound
                        .as_ref()
                        .and_then(|outbound| outbound.awaiting.as_ref())
                        .is_some_and(|awaiting| {
                            awaiting.packet_id == packet_id && awaiting.attempt == attempt
                        });
                    if !should_retry {
                        state.calls.insert(key, call);
                        continue;
                    }
                    if attempt >= CALL_RETRY_LIMIT {
                        self.fail_call(state, peer, call_id, QlError::Timeout);
                        continue;
                    }
                    let frame = call
                        .outbound
                        .as_ref()
                        .and_then(|outbound| outbound.awaiting.as_ref())
                        .map(|awaiting| awaiting.frame.clone())
                        .unwrap();
                    self.send_tracked_frame(state, &mut call, frame, attempt.saturating_add(1));
                    state.calls.insert(key, call);
                }
            }
        }
    }

    fn handle_write_done(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        token: crate::runtime::Token,
        call_id: Option<CallId>,
        packet_id: Option<PacketId>,
        track_ack: bool,
        result: Result<(), QlError>,
    ) {
        if result.is_err() {
            if let Some(call_id) = call_id {
                self.fail_call(state, peer, call_id, QlError::SendFailed);
            }
            let should_disconnect = matches!(
                state.peers.peer(peer).map(|entry| &entry.session),
                Some(crate::runtime::PeerSession::Initiator { handshake_token, .. })
                    if *handshake_token == token
            ) || matches!(
                state.peers.peer(peer).map(|entry| &entry.session),
                Some(crate::runtime::PeerSession::Responder { handshake_token, .. })
                    if *handshake_token == token
            );
            if should_disconnect {
                if let Some(entry) = state.peers.peer_mut(peer) {
                    entry.session = crate::runtime::PeerSession::Disconnected;
                    self.platform.handle_peer_status(peer, &entry.session);
                }
                self.drop_outbound_for_peer(state, peer);
                self.abort_calls_for_peer(state, peer, QlError::SendFailed);
            }
            return;
        }

        if track_ack {
            if let (Some(call_id), Some(packet_id)) = (call_id, packet_id) {
                let attempt = state
                    .calls
                    .get(&(peer, call_id))
                    .and_then(|call| call.outbound.as_ref())
                    .and_then(|outbound| outbound.awaiting.as_ref())
                    .and_then(|awaiting| {
                        (awaiting.packet_id == packet_id).then_some(awaiting.attempt)
                    })
                    .unwrap_or(0);
                state.timeouts.push(Reverse(TimeoutEntry {
                    at: Instant::now() + self.config.packet_ack_timeout,
                    kind: TimeoutKind::CallPacket {
                        peer,
                        call_id,
                        packet_id,
                        attempt,
                    },
                }));
            }
        }
    }
}

trait FrameExt {
    fn call_id(&self) -> CallId;
}

impl FrameExt for CallFrame {
    fn call_id(&self) -> CallId {
        match self {
            CallFrame::Open { call_id, .. }
            | CallFrame::Accept { call_id, .. }
            | CallFrame::Data { call_id, .. }
            | CallFrame::Credit { call_id, .. }
            | CallFrame::Finish { call_id, .. }
            | CallFrame::Reset { call_id, .. } => *call_id,
        }
    }
}
