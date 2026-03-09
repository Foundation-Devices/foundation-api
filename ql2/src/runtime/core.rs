use std::{
    cmp::Reverse, collections::binary_heap::PeekMut, future::Future, io::Read, task::Poll,
    time::Instant,
};

use bc_components::{MLDSAPublicKey, MLKEMPublicKey, SigningPublicKey, XID};
use dcbor::CBOR;
use futures_lite::future::poll_fn;

use crate::{
    platform::{QlPlatform, QlPlatformExt},
    runtime::{
        handle::{CallResponder, InboundByteStream, InboundCall},
        internal::{
            now_secs, peer_hello_wins, AwaitingFrame, AwaitingPacket, CallPhase, CallRecord,
            CallRole, CoreState, HelloAction, InFlightWrite, InboundStreamItem, InboundTerminal,
            InitiatorStage, KeepAliveState, LoopStep, OutboundCallStreamState, OutboundMessage,
            OutboundPayload, RuntimeCommand, RuntimeState, TimeoutEntry, TimeoutKind,
        },
        replay_cache::{ReplayKey, ReplayNamespace},
        AcceptedCallDelivery, HandlerEvent, KeepAliveConfig, PeerSession, Runtime,
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

impl<P: QlPlatform> Runtime<P> {
    pub async fn run(self) {
        let mut state = RuntimeState::new();
        for peer in self.platform.load_peers().await {
            state
                .core
                .peers
                .upsert_peer(peer.peer, peer.signing_key, peer.encapsulation_key);
        }

        let mut in_flight: Option<InFlightWrite<'_>> = None;
        while !self.rx.is_closed() {
            self.drive_calls(&mut state);
            if in_flight.is_none() {
                in_flight = self.start_next_write(&mut state);
            }
            match self.next_step(&state.core, in_flight.as_mut()).await {
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
                        request_pipe,
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
                            request_pipe,
                            accepted,
                            start,
                            config,
                        );
                    }
                    RuntimeCommand::AcceptCall {
                        recipient,
                        call_id,
                        response_head,
                        response_pipe,
                    } => {
                        self.handle_accept_call(
                            &mut state,
                            recipient,
                            call_id,
                            response_head,
                            response_pipe,
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
        while let Some(message) = state.core.outbound.pop_front() {
            let bytes = match message.payload {
                OutboundPayload::PreEncoded(bytes) => bytes,
                OutboundPayload::DeferredCall(body) => {
                    let Some(session_key) = state
                        .core
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
        core: &CoreState,
        mut in_flight: Option<&mut InFlightWrite<'a>>,
    ) -> LoopStep {
        let recv_future = self.rx.recv();
        futures_lite::pin!(recv_future);

        let mut sleep_future = core.timeouts.peek().map(|entry| {
            let deadline = entry.0.at;
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
                .core
                .peers
                .upsert_peer(peer, signing_key, encapsulation_key);
            if let crate::runtime::PeerSession::Disconnected = entry.session {
                self.platform.handle_peer_status(peer, &entry.session);
            }
        }
        self.persist_peers(state);
    }

    fn handle_connect(&self, state: &mut RuntimeState, peer: XID) {
        let (hello, session_key) = {
            let Some(peer_record) = state.core.peers.peer(peer) else {
                return;
            };
            match &peer_record.session {
                PeerSession::Connected { .. }
                | PeerSession::Initiator { .. }
                | PeerSession::Responder { .. } => return,
                PeerSession::Disconnected => match handshake::build_hello(
                    &self.platform,
                    self.platform.xid(),
                    peer,
                    &peer_record.encapsulation_key,
                ) {
                    Ok(result) => result,
                    Err(_) => return,
                },
            }
        };

        let deadline = Instant::now() + self.config.handshake_timeout;
        let token = state.core.next_token();
        if let Some(entry) = state.core.peers.peer_mut(peer) {
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
            &mut state.core,
            peer,
            token,
            deadline,
            CBOR::from(record).to_cbor_data(),
        );
    }

    fn handle_unpair_local(&self, state: &mut RuntimeState, peer: XID) {
        if state.core.peers.peer(peer).is_none() {
            return;
        }
        let record = unpair::build_unpair_record(
            &self.platform,
            QlHeader {
                sender: self.platform.xid(),
                recipient: peer,
            },
            crate::MessageId(state.core.next_packet_id().0),
            now_secs().saturating_add(self.config.packet_expiration.as_secs()),
        );
        self.unpair_peer(state, peer);
        let token = state.core.next_token();
        self.enqueue_handshake_message(
            &mut state.core,
            peer,
            token,
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
        request_pipe: crate::pipe::PipeReader,
        accepted: oneshot::Sender<Result<crate::runtime::AcceptedCallDelivery, QlError>>,
        start: oneshot::Sender<Result<CallId, QlError>>,
        config: crate::runtime::CallConfig,
    ) {
        let Some(entry) = state.core.peers.peer(recipient) else {
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

        let call_id = state.core.next_call_id();
        let (response_tx, response_rx) = async_channel::bounded(1);
        let open_flags = OpenFlags::new(response_expected, false);
        let token = state.core.next_token();
        let mut outbound = OutboundCallStreamState::new(Direction::Request, request_pipe, 0);
        outbound.queue.push_back(CallFrame::Open {
            call_id,
            route_id,
            flags: open_flags,
            request_head: request_head.clone(),
            response_max_offset: self.config.initial_credit,
        });
        let call = CallRecord {
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
        state.core.timeouts.push(Reverse(TimeoutEntry {
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
        response_pipe: crate::pipe::PipeReader,
    ) {
        let key = (recipient, call_id);
        let Some(call) = state.calls.get_mut(&key) else {
            return;
        };
        if call.role != CallRole::Responder || call.phase != CallPhase::ResponderPending {
            return;
        }

        let mut outbound = OutboundCallStreamState::new(
            Direction::Response,
            response_pipe,
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
        let Some(call) = state.calls.get_mut(&key) else {
            return;
        };
        if call.role != CallRole::Responder || call.phase != CallPhase::ResponderPending {
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
        let (mut response_pipe, _response_writer) = crate::pipe::pipe(self.config.pipe_size_bytes);
        response_pipe.close();
        let mut outbound = OutboundCallStreamState::new(
            Direction::Response,
            response_pipe,
            call.initial_remote_credit,
        );
        outbound.closed = true;
        outbound.queue.push_back(frame);
        call.outbound = Some(outbound);
        call.last_activity = Instant::now();
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
        let Some(call) = state.calls.get_mut(&key) else {
            return;
        };
        if call.inbound.dir != dir || call.inbound.closed {
            return;
        }
        call.inbound.max_offset = call.inbound.max_offset.saturating_add(amount);
        self.flush_inbound_terminal(&mut call.inbound);
        self.queue_credit(call, dir);
        call.last_activity = Instant::now();
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
        let Some(call) = state.calls.get_mut(&key) else {
            return;
        };
        if call.local_outbound_dir() != dir {
            return;
        }
        if let Some(outbound) = call.outbound.as_mut() {
            if !outbound.closed {
                outbound.closed = true;
                outbound.queue.clear();
                outbound.pipe.close();
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
        let Some(call) = state.calls.get_mut(&key) else {
            return;
        };
        if call.inbound.dir != dir || call.inbound.closed {
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
            outbound.pipe.close();
        }
        call.last_activity = Instant::now();
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
            .core
            .peers
            .upsert_peer(peer, payload.signing_pub_key, payload.encapsulation_pub_key);
        self.persist_peers(state);
        self.handle_connect(state, peer);
    }

    fn handle_unpair(&self, state: &mut RuntimeState, header: QlHeader, record: UnpairRecord) {
        let peer = header.sender;
        {
            let Some(peer_record) = state.core.peers.peer(peer) else {
                return;
            };
            if unpair::verify_unpair_record(&header, &record, &peer_record.signing_key).is_err() {
                return;
            }
        }
        let replay_key = ReplayKey::new(
            peer,
            ReplayNamespace::Peer,
            crate::MessageId(record.message_id.0),
        );
        if state
            .core
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
        let should_reply = {
            let Some(peer_record) = state.core.peers.peer(peer) else {
                return;
            };
            let PeerSession::Connected {
                session_key,
                keepalive,
            } = &peer_record.session
            else {
                return;
            };
            if heartbeat::decrypt_heartbeat(&header, &encrypted, session_key).is_err() {
                return;
            }
            !keepalive.pending
        };
        self.record_activity(state, peer);
        if should_reply {
            self.send_heartbeat_message(&mut state.core, peer);
        }
    }

    fn handle_call(
        &self,
        state: &mut RuntimeState,
        header: QlHeader,
        encrypted: bc_components::EncryptedMessage,
    ) {
        let peer = header.sender;
        let body = {
            let Some(peer_record) = state.core.peers.peer(peer) else {
                return;
            };
            let PeerSession::Connected { session_key, .. } = &peer_record.session else {
                return;
            };
            match call::decrypt_call(&header, &encrypted, session_key) {
                Ok(body) => body,
                Err(_) => return,
            }
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
            .core
            .replay_cache
            .check_and_store_valid_until(replay_key, body.valid_until)
        {
            return;
        }

        self.record_activity(state, peer);
        self.record_call_activity(state, peer, frame.call_id());
        self.send_packet_ack(&mut state.core, peer, body.packet_id);

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
                &mut state.core,
                peer,
                call_id,
                call::ResetTarget::Both,
                ResetCode::Protocol,
            );
            return;
        }

        let (request_tx, request_rx) = async_channel::bounded(1);
        let responder = CallResponder::new(
            call_id,
            peer,
            self.config.pipe_size_bytes,
            self.tx.upgrade().expect("runtime tx"),
        );
        let mut inbound = crate::runtime::internal::InboundCallStreamState::new(
            Direction::Request,
            request_tx,
            0,
        );
        if flags.request_finished() {
            inbound.terminal = Some(InboundTerminal::Finished);
            self.flush_inbound_terminal(&mut inbound);
        }

        let call = CallRecord {
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
        let mut send_protocol_reset = false;
        let mut fail_protocol = false;
        {
            let Some(call) = state.calls.get_mut(&key) else {
                return;
            };
            if call.role != CallRole::Initiator {
                send_protocol_reset = true;
            } else if let Some(existing) = &call.accept_frame {
                match existing {
                    CallFrame::Accept {
                        call_id: existing_call_id,
                        status: existing_status,
                        response_head: existing_response_head,
                        request_max_offset: existing_request_max_offset,
                    } if *existing_call_id == call_id
                        && existing_status == &status
                        && existing_response_head == &response_head
                        && *existing_request_max_offset == request_max_offset =>
                    {
                        return;
                    }
                    _ => {}
                }
                fail_protocol = true;
            } else {
                if let Some(outbound) = call.outbound.as_mut() {
                    if matches!(
                        outbound.awaiting.as_ref().map(|awaiting| &awaiting.frame),
                        Some(AwaitingFrame::Control(CallFrame::Open { .. }))
                    ) {
                        outbound.awaiting = None;
                    }
                }

                match status {
                    AcceptStatus::Accepted => {
                        call.phase = CallPhase::Open;
                        call.accept_frame = Some(CallFrame::Accept {
                            call_id,
                            status: AcceptStatus::Accepted,
                            response_head: response_head.clone(),
                            request_max_offset,
                        });
                        if let Some(outbound) = call.outbound.as_mut() {
                            outbound.remote_max_offset = request_max_offset;
                            outbound.data_enabled = true;
                        }
                        if let Some(tx) = call.accept_tx.take() {
                            let delivery = call.response_rx.take().map(|rx| AcceptedCallDelivery {
                                peer: call.peer,
                                call_id: call.call_id,
                                response_head,
                                rx,
                                tx: self.tx.upgrade().expect("runtime tx"),
                            });
                            let _ = tx.send(delivery.ok_or(QlError::Cancelled));
                        }
                    }
                    AcceptStatus::Rejected(code) => {
                        call.phase = CallPhase::Rejected;
                        call.accept_frame = Some(CallFrame::Accept {
                            call_id,
                            status: AcceptStatus::Rejected(code),
                            response_head,
                            request_max_offset,
                        });
                        if let Some(outbound) = call.outbound.as_mut() {
                            outbound.closed = true;
                            outbound.queue.clear();
                            outbound.awaiting = None;
                            outbound.pipe.close();
                        }
                        if let Some(tx) = call.accept_tx.take() {
                            let _ = tx.send(Err(QlError::CallRejected { id: call_id, code }));
                        }
                        call.inbound.closed = true;
                        call.inbound.chunk_tx.close();
                    }
                }

                call.last_activity = Instant::now();
            }
        }
        if send_protocol_reset {
            self.send_ephemeral_reset(
                &mut state.core,
                peer,
                call_id,
                call::ResetTarget::Both,
                ResetCode::Protocol,
            );
            return;
        }
        if fail_protocol {
            self.fail_call(state, peer, call_id, QlError::CallProtocol { id: call_id });
            return;
        }
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
        let mut fail_protocol = false;
        {
            let Some(call) = state.calls.get_mut(&key) else {
                return;
            };
            self.note_accept_seen_from_remote(call);
            if call.inbound.dir != dir || call.inbound.closed {
                fail_protocol = true;
            } else if offset < call.inbound.next_offset {
                self.queue_credit(call, dir);
                call.last_activity = Instant::now();
            } else {
                let end = offset.saturating_add(bytes.len() as u64);
                if offset != call.inbound.next_offset || end > call.inbound.max_offset {
                    self.queue_local_reset(call, call::ResetTarget::Both, ResetCode::Protocol);
                } else {
                    call.inbound.next_offset = end;
                    if call.inbound.pending_chunk.is_some() {
                        self.queue_local_reset(call, call::ResetTarget::Both, ResetCode::Protocol);
                    } else {
                        match call
                            .inbound
                            .chunk_tx
                            .try_send(InboundStreamItem::Chunk(bytes))
                        {
                            Ok(()) => {}
                            Err(async_channel::TrySendError::Full(InboundStreamItem::Chunk(
                                chunk,
                            ))) => {
                                call.inbound.pending_chunk = Some(chunk);
                            }
                            Err(async_channel::TrySendError::Closed(_)) => {
                                self.queue_local_reset(
                                    call,
                                    call::ResetTarget::Both,
                                    ResetCode::Cancelled,
                                );
                            }
                            Err(async_channel::TrySendError::Full(_)) => unreachable!(),
                        }
                        self.queue_credit(call, dir);
                    }
                }
                call.last_activity = Instant::now();
            }
        }
        if fail_protocol {
            self.fail_call(state, peer, call_id, QlError::CallProtocol { id: call_id });
            return;
        }
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
        {
            let Some(call) = state.calls.get_mut(&key) else {
                return;
            };
            self.note_accept_seen_from_remote(call);
            let Some(outbound) = call.outbound.as_mut() else {
                return;
            };
            let acked_offset = outbound.pipe.acked_offset();
            let sent_offset = outbound.pipe.sent_offset();
            if outbound.dir != dir
                || recv_offset < acked_offset
                || recv_offset > sent_offset
                || max_offset < recv_offset
            {
                self.queue_local_reset(call, call::ResetTarget::Both, ResetCode::Protocol);
            } else {
                outbound.pipe.ack_to(recv_offset);
                outbound.remote_max_offset = outbound.remote_max_offset.max(max_offset);
                if matches!(
                    outbound.awaiting.as_ref().map(|awaiting| &awaiting.frame),
                    Some(AwaitingFrame::Data { offset, len, .. })
                        if recv_offset >= offset.saturating_add(*len as u64)
                ) {
                    outbound.awaiting = None;
                }
            }
            call.last_activity = Instant::now();
        }
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
        let Some(call) = state.calls.get_mut(&key) else {
            return;
        };
        self.note_accept_seen_from_remote(call);
        if call.inbound.dir != dir || call.inbound.closed {
            return;
        }
        call.inbound.terminal = Some(InboundTerminal::Finished);
        self.flush_inbound_terminal(&mut call.inbound);
        call.last_activity = Instant::now();
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
        let Some(call) = state.calls.get_mut(&key) else {
            return;
        };
        self.note_accept_seen_from_remote(call);
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
                outbound.awaiting = None;
                outbound.closed = true;
                outbound.pipe.close();
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
        let Some(call) = state.calls.get_mut(&key) else {
            return;
        };
        let Some(outbound) = call.outbound.as_mut() else {
            return;
        };
        let Some(awaiting) = outbound.awaiting.take() else {
            return;
        };

        match awaiting.frame {
            AwaitingFrame::Control(CallFrame::Open { .. }) => {
                if call.phase == CallPhase::InitiatorOpening {
                    call.phase = CallPhase::InitiatorWaitingAccept;
                }
            }
            AwaitingFrame::Control(CallFrame::Accept {
                status: AcceptStatus::Accepted,
                ..
            }) => {
                if call.phase == CallPhase::ResponderAccepting {
                    call.phase = CallPhase::Open;
                    outbound.data_enabled = true;
                }
            }
            AwaitingFrame::Control(CallFrame::Accept {
                status: AcceptStatus::Rejected(_),
                ..
            }) => {
                call.phase = CallPhase::Rejected;
                outbound.closed = true;
                outbound.pipe.close();
            }
            AwaitingFrame::Control(CallFrame::Finish { .. }) => {
                outbound.pipe.close();
            }
            AwaitingFrame::Control(CallFrame::Reset { dir, .. }) => {
                let affects_outbound = match (dir, outbound.dir) {
                    (call::ResetTarget::Request, Direction::Request)
                    | (call::ResetTarget::Response, Direction::Response)
                    | (call::ResetTarget::Both, _) => true,
                    _ => false,
                };
                if affects_outbound {
                    outbound.pipe.close();
                }
            }
            AwaitingFrame::Control(CallFrame::Data { .. } | CallFrame::Credit { .. }) => {}
            AwaitingFrame::Data { .. } => {}
        }

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
        let (calls, core) = (&mut state.calls, &mut state.core);
        let Some(call) = calls.get_mut(&key) else {
            return;
        };
        let Some(_) = call.outbound.as_ref() else {
            return;
        };

        let mut next_control = None;
        let mut next_data = None;
        {
            let outbound = call.outbound.as_mut().unwrap();
            if outbound.awaiting.is_none() {
                if let Some(frame) = outbound.queue.pop_front() {
                    next_control = Some(frame);
                } else if outbound.data_enabled && !outbound.closed {
                    if let Some(mut send) = outbound
                        .pipe
                        .reserve_send(outbound.remote_max_offset, self.config.max_payload_bytes)
                    {
                        let mut bytes = vec![0; send.len()];
                        // TODO: We still allocate and copy per outbound packet because the wire
                        // format owns `Vec<u8>`. The ring eliminates the long-lived stream buffer
                        // allocations but not this packet build step.
                        send.read_exact(&mut bytes).expect("grant length is exact");
                        next_data = Some((outbound.dir, send.offset(), send.len(), bytes));
                    } else if outbound.pipe.writer_finished() && outbound.pipe.all_sent() {
                        outbound.closed = true;
                        next_control = Some(CallFrame::Finish {
                            call_id,
                            dir: outbound.dir,
                        });
                    }
                }
            }
        }

        if let Some(frame) = next_control {
            self.send_control_frame(core, call, frame, 0);
        } else if let Some((dir, offset, len, bytes)) = next_data {
            self.send_data_frame(core, call, dir, offset, len, bytes, 0);
        }
    }

    fn send_control_frame(
        &self,
        core: &mut CoreState,
        call: &mut CallRecord,
        frame: CallFrame,
        attempt: u8,
    ) {
        let packet_id = core.next_packet_id();
        let Some(outbound) = call.outbound.as_mut() else {
            return;
        };
        outbound.awaiting = Some(AwaitingPacket {
            packet_id,
            frame: AwaitingFrame::Control(frame.clone()),
            attempt,
        });
        let valid_until = now_secs().saturating_add(self.config.packet_expiration.as_secs());
        self.enqueue_call_body(
            core,
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

    fn send_data_frame(
        &self,
        core: &mut CoreState,
        call: &mut CallRecord,
        dir: Direction,
        offset: u64,
        len: usize,
        bytes: Vec<u8>,
        attempt: u8,
    ) {
        let packet_id = core.next_packet_id();
        let Some(outbound) = call.outbound.as_mut() else {
            return;
        };
        outbound.awaiting = Some(AwaitingPacket {
            packet_id,
            frame: AwaitingFrame::Data { dir, offset, len },
            attempt,
        });
        let valid_until = now_secs().saturating_add(self.config.packet_expiration.as_secs());
        self.enqueue_call_body(
            core,
            call.peer,
            Some(call.call_id),
            Some(packet_id),
            true,
            false,
            CallBody {
                packet_id,
                valid_until,
                packet_ack: None,
                frame: Some(CallFrame::Data {
                    call_id: call.call_id,
                    dir,
                    offset,
                    bytes,
                }),
            },
        );
    }

    fn queue_credit(&self, call: &mut CallRecord, dir: Direction) {
        if let Some(outbound) = call.outbound.as_mut() {
            outbound.queue.push_back(CallFrame::Credit {
                call_id: call.call_id,
                dir,
                recv_offset: call.inbound.next_offset,
                max_offset: call.inbound.max_offset,
            });
        }
    }

    fn queue_local_reset(&self, call: &mut CallRecord, dir: call::ResetTarget, code: ResetCode) {
        if let Some(outbound) = call.outbound.as_mut() {
            outbound.queue.clear();
            outbound.queue.push_back(CallFrame::Reset {
                call_id: call.call_id,
                dir,
                code,
            });
            outbound.closed = true;
            // TODO: This closes the local writer before the reset frame is acknowledged.
            // That matches the old cancel-fast behavior, but we may want a stricter contract later.
            outbound.pipe.close();
        }
        call.inbound.closed = true;
        call.inbound.pending_chunk = None;
        call.inbound.terminal = Some(InboundTerminal::Error(QlError::CallProtocol {
            id: call.call_id,
        }));
        self.flush_inbound_terminal(&mut call.inbound);
    }

    fn note_accept_seen_from_remote(&self, call: &mut CallRecord) {
        if call.role != CallRole::Responder || call.phase != CallPhase::ResponderAccepting {
            return;
        }
        let Some(outbound) = call.outbound.as_mut() else {
            return;
        };
        if matches!(
            outbound.awaiting.as_ref().map(|awaiting| &awaiting.frame),
            Some(AwaitingFrame::Control(CallFrame::Accept { .. }))
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
                outbound.pipe.close();
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

    fn send_packet_ack(&self, core: &mut CoreState, peer: XID, acked_packet: PacketId) {
        let packet_id = core.next_packet_id();
        let valid_until = now_secs().saturating_add(self.config.packet_expiration.as_secs());
        self.enqueue_call_body(
            core,
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
        core: &mut CoreState,
        peer: XID,
        call_id: CallId,
        dir: call::ResetTarget,
        code: ResetCode,
    ) {
        let packet_id = core.next_packet_id();
        let valid_until = now_secs().saturating_add(self.config.packet_expiration.as_secs());
        self.enqueue_call_body(
            core,
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
        core: &mut CoreState,
        peer: XID,
        token: crate::runtime::Token,
        deadline: Instant,
        bytes: Vec<u8>,
    ) {
        core.outbound.push_back(OutboundMessage {
            peer,
            token,
            call_id: None,
            packet_id: None,
            track_ack: false,
            payload: OutboundPayload::PreEncoded(bytes),
        });
        core.timeouts.push(Reverse(TimeoutEntry {
            at: deadline,
            kind: TimeoutKind::Handshake { peer, token },
        }));
        core.timeouts.push(Reverse(TimeoutEntry {
            at: deadline,
            kind: TimeoutKind::Outbound { token },
        }));
    }

    fn enqueue_call_body(
        &self,
        core: &mut CoreState,
        peer: XID,
        call_id: Option<CallId>,
        packet_id: Option<PacketId>,
        track_ack: bool,
        priority: bool,
        body: CallBody,
    ) {
        let token = core.next_token();
        let message = OutboundMessage {
            peer,
            token,
            call_id,
            packet_id,
            track_ack,
            payload: OutboundPayload::DeferredCall(body),
        };
        if priority {
            core.outbound.push_front(message);
        } else {
            core.outbound.push_back(message);
        }
        core.timeouts.push(Reverse(TimeoutEntry {
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
        let action = match state.core.peers.peer(peer) {
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
                let token = state.core.next_token();
                self.enqueue_handshake_message(
                    &mut state.core,
                    peer,
                    token,
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
        let confirm = match {
            let Some(peer_record) = state.core.peers.peer(peer) else {
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
                &self.platform,
                self.platform.xid(),
                peer,
                &peer_record.signing_key,
                hello,
                &reply,
                session_key,
            )
        } {
            Ok((confirm, session_key)) => {
                if let Some(entry) = state.core.peers.peer_mut(peer) {
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
                if let Some(entry) = state.core.peers.peer_mut(peer) {
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
        let token = state.core.next_token();
        self.enqueue_handshake_message(
            &mut state.core,
            peer,
            token,
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
        let Some(peer_record) = state.core.peers.peer(peer) else {
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
            self.platform.xid(),
            &peer_record.signing_key,
            &hello,
            &reply,
            &confirm,
            &secrets,
        ) {
            Ok(session_key) => {
                if let Some(entry) = state.core.peers.peer_mut(peer) {
                    entry.session = crate::runtime::PeerSession::Connected {
                        session_key,
                        keepalive: KeepAliveState::new(),
                    };
                    self.platform.handle_peer_status(peer, &entry.session);
                }
                self.record_activity(state, peer);
            }
            Err(_) => {
                if let Some(entry) = state.core.peers.peer_mut(peer) {
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
        let (reply, secrets) = match {
            let Some(peer_record) = state.core.peers.peer(peer) else {
                return;
            };
            handshake::respond_hello(
                &self.platform,
                peer,
                self.platform.xid(),
                &peer_record.encapsulation_key,
                &hello,
            )
        } {
            Ok(result) => result,
            Err(_) => {
                if let Some(entry) = state.core.peers.peer_mut(peer) {
                    entry.session = crate::runtime::PeerSession::Disconnected;
                    self.platform.handle_peer_status(peer, &entry.session);
                }
                return;
            }
        };

        let deadline = Instant::now() + self.config.handshake_timeout;
        let token = state.core.next_token();
        if let Some(entry) = state.core.peers.peer_mut(peer) {
            entry.session = PeerSession::Responder {
                handshake_token: token,
                hello,
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
            &mut state.core,
            peer,
            token,
            deadline,
            CBOR::from(record).to_cbor_data(),
        );
    }

    fn send_heartbeat_message(&self, core: &mut CoreState, peer: XID) {
        let message_id = MessageId(core.next_packet_id().0);
        let token = core.next_token();
        let deadline = Instant::now() + self.config.packet_expiration;
        let message = {
            let Some(peer_record) = core.peers.peer(peer) else {
                return;
            };
            let PeerSession::Connected { session_key, .. } = &peer_record.session else {
                return;
            };
            heartbeat::encrypt_heartbeat(
                QlHeader {
                    sender: self.platform.xid(),
                    recipient: peer,
                },
                session_key,
                HeartbeatBody {
                    message_id,
                    valid_until: now_secs().saturating_add(self.config.packet_expiration.as_secs()),
                },
            )
        };
        self.enqueue_handshake_message(
            core,
            peer,
            token,
            deadline,
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
        let token = state.core.next_token();
        let Some(entry) = state.core.peers.peer_mut(peer) else {
            return;
        };
        let crate::runtime::PeerSession::Connected { keepalive, .. } = &mut entry.session else {
            return;
        };
        let now = Instant::now();
        keepalive.last_activity = Some(now);
        keepalive.pending = false;
        keepalive.token = token;
        state.core.timeouts.push(Reverse(TimeoutEntry {
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
        self.platform.persist_peers(state.core.peers.all());
    }

    fn drop_outbound_for_peer(&self, state: &mut RuntimeState, peer: XID) {
        let call_ids: Vec<_> = state
            .core
            .outbound
            .iter()
            .filter(|message| message.peer == peer)
            .filter_map(|message| message.call_id)
            .collect();
        state.core.outbound.retain(|message| message.peer != peer);
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
            outbound.awaiting = None;
            outbound.closed = true;
            outbound.pipe.close();
        }
        call.inbound.pending_chunk = None;
        let _ = call
            .inbound
            .chunk_tx
            .try_send(InboundStreamItem::Error(error));
        call.inbound.chunk_tx.close();
    }

    fn unpair_peer(&self, state: &mut RuntimeState, peer: XID) {
        if state.core.peers.remove_peer(peer).is_none() {
            return;
        }
        self.drop_outbound_for_peer(state, peer);
        self.abort_calls_for_peer(state, peer, QlError::SendFailed);
        state.core.replay_cache.clear_peer(peer);
        self.platform
            .handle_peer_status(peer, &crate::runtime::PeerSession::Disconnected);
        self.persist_peers(state);
    }

    fn handle_timeouts(&self, state: &mut RuntimeState) {
        let now = Instant::now();
        loop {
            let Some(entry) = state.core.timeouts.peek_mut().filter(|e| e.0.at <= now) else {
                break;
            };
            let entry = PeekMut::pop(entry).0;
            match entry.kind {
                TimeoutKind::Outbound { token } => {
                    let mut timed_out_call = None;
                    state.core.outbound.retain(|message| {
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
                    let Some(entry) = state.core.peers.peer(peer) else {
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
                        if let Some(entry) = state.core.peers.peer_mut(peer) {
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
                    let should_send = {
                        let Some(entry) = state.core.peers.peer(peer) else {
                            continue;
                        };
                        let PeerSession::Connected { keepalive, .. } = &entry.session else {
                            continue;
                        };
                        if keepalive.token == token && !keepalive.pending {
                            true
                        } else {
                            continue;
                        }
                    };
                    if should_send {
                        self.send_heartbeat_message(&mut state.core, peer);
                    }
                    if let Some(entry) = state.core.peers.peer_mut(peer) {
                        if let crate::runtime::PeerSession::Connected { keepalive, .. } =
                            &mut entry.session
                        {
                            if keepalive.token == token {
                                keepalive.pending = true;
                            }
                        }
                    }
                    state.core.timeouts.push(Reverse(TimeoutEntry {
                        at: now + config.timeout,
                        kind: TimeoutKind::KeepAliveTimeout { peer, token },
                    }));
                }
                TimeoutKind::KeepAliveTimeout { peer, token } => {
                    let Some(entry) = state.core.peers.peer(peer) else {
                        continue;
                    };
                    let should_disconnect = match &entry.session {
                        crate::runtime::PeerSession::Connected { keepalive, .. } => {
                            keepalive.token == token && keepalive.pending
                        }
                        _ => false,
                    };
                    if should_disconnect {
                        if let Some(entry) = state.core.peers.peer_mut(peer) {
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
                    let mut timed_out = false;
                    {
                        let (calls, core) = (&mut state.calls, &mut state.core);
                        let Some(call) = calls.get_mut(&key) else {
                            continue;
                        };
                        let Some(awaiting) = call
                            .outbound
                            .as_ref()
                            .and_then(|outbound| outbound.awaiting.as_ref())
                        else {
                            continue;
                        };
                        if awaiting.packet_id != packet_id || awaiting.attempt != attempt {
                            continue;
                        }
                        if attempt >= self.config.call_retry_limit {
                            timed_out = true;
                        } else {
                            match &awaiting.frame {
                                AwaitingFrame::Control(frame) => {
                                    self.send_control_frame(
                                        core,
                                        call,
                                        frame.clone(),
                                        attempt.saturating_add(1),
                                    );
                                }
                                AwaitingFrame::Data { dir, offset, len } => {
                                    let Some(outbound) = call.outbound.as_ref() else {
                                        continue;
                                    };
                                    let Some(mut grant) = outbound.pipe.retry_send(*offset, *len)
                                    else {
                                        // TODO: If a later `Credit` advanced past this range, the
                                        // bytes are already semantically acked and cannot be retried.
                                        continue;
                                    };
                                    let mut bytes = vec![0; grant.len()];
                                    grant.read_exact(&mut bytes).expect("grant length is exact");
                                    self.send_data_frame(
                                        core,
                                        call,
                                        *dir,
                                        *offset,
                                        *len,
                                        bytes,
                                        attempt.saturating_add(1),
                                    );
                                }
                            }
                        }
                    }
                    if timed_out {
                        self.fail_call(state, peer, call_id, QlError::Timeout);
                    }
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
                state.core.peers.peer(peer).map(|entry| &entry.session),
                Some(crate::runtime::PeerSession::Initiator { handshake_token, .. })
                    if *handshake_token == token
            ) || matches!(
                state.core.peers.peer(peer).map(|entry| &entry.session),
                Some(crate::runtime::PeerSession::Responder { handshake_token, .. })
                    if *handshake_token == token
            );
            if should_disconnect {
                if let Some(entry) = state.core.peers.peer_mut(peer) {
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
                state.core.timeouts.push(Reverse(TimeoutEntry {
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
