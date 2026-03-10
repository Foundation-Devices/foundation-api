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
        handle::{InboundByteStream, InboundStream, StreamResponder},
        internal::{
            now_secs, peer_hello_wins, AwaitingFrame, AwaitingPacket, CoreState, HelloAction,
            InFlightWrite, InboundBody, InitiatorAccept, InitiatorStage, InitiatorStream,
            KeepAliveState, LoopStep, OutboundBody, OutboundMessage, OutboundPayload,
            PendingAcceptTx, ResponderResponse, ResponderStream, RuntimeCommand, RuntimeState,
            SetupFrame, StreamControl, StreamMeta, StreamState, TimeoutEntry, TimeoutKind,
        },
        replay_cache::{ReplayKey, ReplayNamespace},
        AcceptedStreamDelivery, HandlerEvent, KeepAliveConfig, PeerSession, Runtime,
    },
    wire::{
        handshake::{self, HandshakeRecord},
        heartbeat::{self, HeartbeatBody},
        pair::{self, PairRequestRecord},
        stream::{
            self, Direction, RejectCode, ResetCode, StreamBody, StreamFrame, StreamFrameAccept,
            StreamFrameCredit, StreamFrameData, StreamFrameFinish, StreamFrameOpen,
            StreamFrameReject, StreamFrameReset,
        },
        unpair::{self, UnpairRecord},
        QlHeader, QlPayload, QlRecord,
    },
    MessageId, PacketId, QlError, RouteId, StreamId,
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
            self.drive_streams(&mut state);
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
                    RuntimeCommand::OpenStream {
                        recipient,
                        route_id,
                        request_head,
                        request_pipe,
                        accepted,
                        start,
                        config,
                    } => {
                        self.handle_open_stream(
                            &mut state,
                            recipient,
                            route_id,
                            request_head,
                            request_pipe,
                            accepted,
                            start,
                            config,
                        );
                    }
                    RuntimeCommand::AcceptStream {
                        recipient,
                        stream_id,
                        response_head,
                        response_pipe,
                    } => {
                        self.handle_accept_stream(
                            &mut state,
                            recipient,
                            stream_id,
                            response_head,
                            response_pipe,
                        );
                    }
                    RuntimeCommand::RejectStream {
                        recipient,
                        stream_id,
                        code,
                    } => {
                        self.handle_reject_stream(&mut state, recipient, stream_id, code);
                    }
                    RuntimeCommand::PollStream { peer, stream_id } => {
                        self.drive_stream(&mut state, peer, stream_id);
                    }
                    RuntimeCommand::AdvanceInboundCredit {
                        sender,
                        stream_id,
                        dir,
                        amount,
                    } => {
                        self.handle_advance_inbound_credit(
                            &mut state, sender, stream_id, dir, amount,
                        );
                    }
                    RuntimeCommand::ResetOutbound {
                        recipient,
                        stream_id,
                        dir,
                        code,
                    } => {
                        self.handle_reset_outbound(&mut state, recipient, stream_id, dir, code);
                    }
                    RuntimeCommand::ResetInbound {
                        sender,
                        stream_id,
                        dir,
                        code,
                    } => {
                        self.handle_reset_inbound(&mut state, sender, stream_id, dir, code);
                    }
                    RuntimeCommand::ResponderDropped { sender, stream_id } => {
                        self.handle_responder_dropped(&mut state, sender, stream_id);
                    }
                    RuntimeCommand::PendingAcceptDropped {
                        recipient,
                        stream_id,
                    } => {
                        self.handle_pending_accept_dropped(&mut state, recipient, stream_id);
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
                    stream_id,
                    packet_id,
                    track_ack,
                    result,
                } => {
                    in_flight = None;
                    self.handle_write_done(
                        &mut state, peer, token, stream_id, packet_id, track_ack, result,
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
                OutboundPayload::DeferredStream(body) => {
                    let Some(session_key) = state
                        .core
                        .peers
                        .peer(message.peer)
                        .and_then(|entry| entry.session.session_key())
                    else {
                        if let Some(stream_id) = message.stream_id {
                            self.fail_stream(state, message.peer, stream_id, QlError::SendFailed);
                        }
                        continue;
                    };
                    let record = stream::encrypt_stream(
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
                stream_id: message.stream_id,
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
                        stream_id: in_flight.stream_id,
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

    fn handle_open_stream(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        route_id: RouteId,
        request_head: Vec<u8>,
        request_pipe: crate::pipe::PipeReader<QlError>,
        accepted: oneshot::Sender<Result<crate::runtime::AcceptedStreamDelivery, QlError>>,
        start: oneshot::Sender<Result<StreamId, QlError>>,
        config: crate::runtime::StreamConfig,
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

        let stream_id = state.core.next_stream_id();
        let (response_reader, response_writer) = crate::pipe::pipe(self.config.pipe_size_bytes);
        let token = state.core.next_token();
        let mut control = StreamControl::new();
        control.pending.set_setup(SetupFrame::Open(StreamFrameOpen {
            stream_id,
            route_id,
            request_head: request_head.clone(),
            response_max_offset: self.config.initial_credit,
        }));
        let stream = StreamState::Initiator(InitiatorStream {
            meta: StreamMeta {
                key: crate::runtime::internal::StreamKey {
                    peer: recipient,
                    stream_id,
                },
                route_id,
                request_head,
                last_activity: Instant::now(),
            },
            control,
            request: OutboundBody::new(Direction::Request, request_pipe, 0, false),
            response: InboundBody::new(response_writer, self.config.initial_credit),
            accept: InitiatorAccept::Opening {
                accept_waiter: Some(PendingAcceptTx {
                    tx: Some(accepted),
                    response_reader: Some(response_reader),
                }),
                open_timeout_token: token,
            },
        });
        state.streams.insert((recipient, stream_id), stream);
        state.core.timeouts.push(Reverse(TimeoutEntry {
            at: Instant::now() + timeout,
            kind: TimeoutKind::StreamOpen {
                peer: recipient,
                stream_id,
                token,
            },
        }));
        let _ = start.send(Ok(stream_id));
        self.drive_stream(state, recipient, stream_id);
    }

    fn handle_accept_stream(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        stream_id: StreamId,
        response_head: Vec<u8>,
        response_pipe: crate::pipe::PipeReader<QlError>,
    ) {
        let key = (recipient, stream_id);
        let Some(StreamState::Responder(stream)) = state.streams.get_mut(&key) else {
            return;
        };
        let ResponderResponse::Pending { initial_credit } = stream.response else {
            return;
        };
        let frame = StreamFrameAccept {
            stream_id,
            response_head: response_head.clone(),
            request_max_offset: self.config.initial_credit,
        };
        stream.control.pending.set_setup(SetupFrame::Accept(frame));
        stream.request.max_offset = self.config.initial_credit;
        stream.response = ResponderResponse::Accepted {
            initial_credit,
            body: OutboundBody::new(Direction::Response, response_pipe, initial_credit, false),
        };
        stream.meta.last_activity = Instant::now();
        self.drive_stream(state, recipient, stream_id);
    }

    fn handle_reject_stream(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        stream_id: StreamId,
        code: RejectCode,
    ) {
        let key = (recipient, stream_id);
        let Some(StreamState::Responder(stream)) = state.streams.get_mut(&key) else {
            return;
        };
        let ResponderResponse::Pending { initial_credit } = stream.response else {
            return;
        };
        stream.request.closed = true;
        stream.request.pipe.fail(QlError::Cancelled);
        stream
            .control
            .pending
            .set_setup(SetupFrame::Reject(StreamFrameReject { stream_id, code }));
        stream.response = ResponderResponse::Rejecting {
            initial_credit,
        };
        stream.meta.last_activity = Instant::now();
        self.drive_stream(state, recipient, stream_id);
    }

    fn handle_advance_inbound_credit(
        &self,
        state: &mut RuntimeState,
        sender: XID,
        stream_id: StreamId,
        dir: Direction,
        amount: u64,
    ) {
        let key = (sender, stream_id);
        let Some(stream) = state.streams.get_mut(&key) else {
            return;
        };
        let Some(inbound) = stream.inbound_mut(dir) else {
            return;
        };
        if inbound.closed {
            return;
        }
        inbound.max_offset = inbound.max_offset.saturating_add(amount);
        self.queue_credit(stream, dir);
        *stream.last_activity_mut() = Instant::now();
        self.drive_stream(state, sender, stream_id);
    }

    fn handle_reset_outbound(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        stream_id: StreamId,
        dir: Direction,
        code: ResetCode,
    ) {
        let key = (recipient, stream_id);
        let Some(stream) = state.streams.get_mut(&key) else {
            return;
        };
        let target = reset_target_for_dir(dir);
        let should_reset = {
            let Some(outbound) = stream.outbound_mut(dir) else {
                return;
            };
            if !outbound.closed {
                outbound.closed = true;
                outbound.pipe.close();
                true
            } else {
                false
            }
        };
        if should_reset {
            stream.control_mut().pending.set_reset(target, code);
        }
        *stream.last_activity_mut() = Instant::now();
        self.drive_stream(state, recipient, stream_id);
    }

    fn handle_reset_inbound(
        &self,
        state: &mut RuntimeState,
        sender: XID,
        stream_id: StreamId,
        dir: Direction,
        code: ResetCode,
    ) {
        let key = (sender, stream_id);
        let Some(stream) = state.streams.get_mut(&key) else {
            return;
        };
        let Some(inbound) = stream.inbound_mut(dir) else {
            return;
        };
        if inbound.closed {
            return;
        }
        inbound.closed = true;
        inbound.pipe.close();
        stream
            .control_mut()
            .pending
            .set_reset(reset_target_for_dir(dir), code);
        *stream.last_activity_mut() = Instant::now();
        self.drive_stream(state, sender, stream_id);
    }

    fn handle_responder_dropped(&self, state: &mut RuntimeState, sender: XID, stream_id: StreamId) {
        self.handle_reject_stream(state, sender, stream_id, RejectCode::Unhandled);
    }

    fn handle_pending_accept_dropped(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        stream_id: StreamId,
    ) {
        let key = (recipient, stream_id);
        let Some(stream) = state.streams.get_mut(&key) else {
            return;
        };
        match stream {
            StreamState::Initiator(stream) => match &mut stream.accept {
                InitiatorAccept::Opening { accept_waiter, .. }
                | InitiatorAccept::WaitingAccept { accept_waiter, .. } => {
                    *accept_waiter = None;
                }
                InitiatorAccept::Open { .. } => {}
            },
            _ => {}
        }
        self.maybe_reap_stream(state, recipient, stream_id);
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
            QlPayload::Stream(encrypted) => self.handle_stream(state, header, encrypted),
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

    fn handle_stream(
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
            match stream::decrypt_stream(&header, &encrypted, session_key) {
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
        self.record_stream_activity(state, peer, frame.stream_id());
        self.send_packet_ack(&mut state.core, peer, body.packet_id);

        match frame {
            StreamFrame::Open(StreamFrameOpen {
                stream_id,
                route_id,
                request_head,
                response_max_offset,
            }) => self.handle_stream_open(
                state,
                peer,
                stream_id,
                route_id,
                request_head,
                response_max_offset,
            ),
            StreamFrame::Accept(StreamFrameAccept {
                stream_id,
                response_head,
                request_max_offset,
            }) => {
                self.handle_stream_accept(state, peer, stream_id, response_head, request_max_offset)
            }
            StreamFrame::Reject(StreamFrameReject { stream_id, code }) => {
                self.handle_stream_reject(state, peer, stream_id, code)
            }
            StreamFrame::Data(StreamFrameData {
                stream_id,
                dir,
                offset,
                bytes,
            }) => self.handle_stream_data(state, peer, stream_id, dir, offset, bytes),
            StreamFrame::Credit(StreamFrameCredit {
                stream_id,
                dir,
                recv_offset,
                max_offset,
            }) => self.handle_stream_credit(state, peer, stream_id, dir, recv_offset, max_offset),
            StreamFrame::Finish(StreamFrameFinish { stream_id, dir }) => {
                self.handle_stream_finish(state, peer, stream_id, dir)
            }
            StreamFrame::Reset(StreamFrameReset {
                stream_id,
                dir,
                code,
            }) => self.handle_stream_reset(state, peer, stream_id, dir, code),
        }
    }

    fn handle_stream_open(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        stream_id: StreamId,
        route_id: RouteId,
        request_head: Vec<u8>,
        response_max_offset: u64,
    ) {
        let key = (peer, stream_id);
        if let Some(stream) = state.streams.get(&key) {
            if self.stream_matches_open(stream, route_id, &request_head, response_max_offset) {
                return;
            }
            self.send_ephemeral_reset(
                &mut state.core,
                peer,
                stream_id,
                stream::ResetTarget::Both,
                ResetCode::Protocol,
            );
            return;
        }

        let (request_reader, request_writer) = crate::pipe::pipe(self.config.pipe_size_bytes);
        let responder = StreamResponder::new(
            stream_id,
            peer,
            self.config.pipe_size_bytes,
            self.tx.upgrade().expect("runtime tx"),
        );
        let stream = StreamState::Responder(ResponderStream {
            meta: StreamMeta {
                key: crate::runtime::internal::StreamKey { peer, stream_id },
                route_id,
                request_head: request_head.clone(),
                last_activity: Instant::now(),
            },
            control: StreamControl::new(),
            request: InboundBody::new(request_writer, 0),
            response: ResponderResponse::Pending {
                initial_credit: response_max_offset,
            },
        });
        state.streams.insert(key, stream);
        self.platform
            .handle_inbound(HandlerEvent::Stream(InboundStream {
                sender: peer,
                recipient: self.platform.xid(),
                route_id,
                stream_id,
                request_head,
                request: InboundByteStream::new(
                    peer,
                    stream_id,
                    Direction::Request,
                    request_reader,
                    self.tx.upgrade().expect("runtime tx"),
                ),
                respond_to: responder,
            }));
    }

    fn handle_stream_accept(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        stream_id: StreamId,
        response_head: Vec<u8>,
        request_max_offset: u64,
    ) {
        let key = (peer, stream_id);
        let mut protocol = false;
        {
            let (streams, core) = (&mut state.streams, &mut state.core);
            let Some(stream) = streams.get_mut(&key) else {
                return;
            };
            match stream {
                StreamState::Initiator(stream) => match &mut stream.accept {
                    InitiatorAccept::Opening { accept_waiter, .. } => {
                        if matches!(
                            stream
                                .control
                                .awaiting
                                .as_ref()
                                .map(|awaiting| &awaiting.frame),
                            Some(AwaitingFrame::Control(StreamFrame::Open(_)))
                        ) {
                            stream.control.awaiting = None;
                        }
                        stream.request.remote_max_offset = request_max_offset;
                        stream.request.data_enabled = true;
                        if let Some(mut waiter) = accept_waiter.take() {
                            if let (Some(tx), Some(response_reader)) =
                                (waiter.tx.take(), waiter.response_reader.take())
                            {
                                let _ = tx.send(Ok(AcceptedStreamDelivery {
                                    peer,
                                    stream_id,
                                    response_head: response_head.clone(),
                                    response: response_reader,
                                    tx: self.tx.upgrade().expect("runtime tx"),
                                }));
                            } else {
                                stream.response.closed = true;
                                stream.response.pipe.close();
                                stream
                                    .control
                                    .pending
                                    .set_reset(stream::ResetTarget::Response, ResetCode::Cancelled);
                            }
                        }
                        stream.accept = InitiatorAccept::Open { response_head };
                        stream.meta.last_activity = Instant::now();
                        self.drive_outbound(
                            core,
                            stream.meta.key,
                            &mut stream.control,
                            Some(&mut stream.request),
                        );
                    }
                    InitiatorAccept::WaitingAccept { accept_waiter, .. } => {
                        stream.request.remote_max_offset = request_max_offset;
                        stream.request.data_enabled = true;
                        if let Some(mut waiter) = accept_waiter.take() {
                            if let (Some(tx), Some(response_reader)) =
                                (waiter.tx.take(), waiter.response_reader.take())
                            {
                                let _ = tx.send(Ok(AcceptedStreamDelivery {
                                    peer,
                                    stream_id,
                                    response_head: response_head.clone(),
                                    response: response_reader,
                                    tx: self.tx.upgrade().expect("runtime tx"),
                                }));
                            } else {
                                stream.response.closed = true;
                                stream.response.pipe.close();
                                stream
                                    .control
                                    .pending
                                    .set_reset(stream::ResetTarget::Response, ResetCode::Cancelled);
                            }
                        }
                        stream.accept = InitiatorAccept::Open { response_head };
                        stream.meta.last_activity = Instant::now();
                        self.drive_outbound(
                            core,
                            stream.meta.key,
                            &mut stream.control,
                            Some(&mut stream.request),
                        );
                    }
                    InitiatorAccept::Open {
                        response_head: existing,
                    } => {
                        if *existing != response_head
                            || stream.request.remote_max_offset != request_max_offset
                        {
                            protocol = true;
                        }
                    }
                },
                _ => {
                    protocol = true;
                }
            }
        }

        if protocol {
            self.send_ephemeral_reset(
                &mut state.core,
                peer,
                stream_id,
                stream::ResetTarget::Both,
                ResetCode::Protocol,
            );
        }
    }

    fn handle_stream_reject(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        stream_id: StreamId,
        code: RejectCode,
    ) {
        let key = (peer, stream_id);
        let mut protocol = false;
        let mut remove_after = false;
        {
            let Some(stream) = state.streams.get_mut(&key) else {
                return;
            };
            match stream {
                StreamState::Initiator(stream) => match &mut stream.accept {
                    InitiatorAccept::Opening { accept_waiter, .. }
                    | InitiatorAccept::WaitingAccept { accept_waiter, .. } => {
                        if let Some(mut waiter) = accept_waiter.take() {
                            if let Some(tx) = waiter.tx.take() {
                                let _ = tx.send(Err(QlError::StreamRejected {
                                    id: stream_id,
                                    code,
                                }));
                            }
                        }
                        stream.request.pipe.close();
                        stream.response.pipe.close();
                        remove_after = true;
                    }
                    InitiatorAccept::Open { .. } => {
                        protocol = true;
                    }
                },
                _ => {
                    protocol = true;
                }
            }
        }
        if remove_after {
            state.streams.remove(&key);
        }
        if protocol {
            self.send_ephemeral_reset(
                &mut state.core,
                peer,
                stream_id,
                stream::ResetTarget::Both,
                ResetCode::Protocol,
            );
        }
    }

    fn handle_stream_data(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        stream_id: StreamId,
        dir: Direction,
        offset: u64,
        bytes: Vec<u8>,
    ) {
        let key = (peer, stream_id);
        let Some(stream) = state.streams.get_mut(&key) else {
            return;
        };
        self.note_setup_seen_from_remote(stream);
        if dir == Direction::Response
            && matches!(
                stream,
                StreamState::Initiator(crate::runtime::internal::InitiatorStream {
                    accept: InitiatorAccept::Opening { .. } | InitiatorAccept::WaitingAccept { .. },
                    ..
                })
            )
        {
            self.queue_protocol_reset(stream);
            *stream.last_activity_mut() = Instant::now();
            self.drive_stream(state, peer, stream_id);
            return;
        }
        let Some(inbound) = stream.inbound_mut(dir) else {
            self.queue_protocol_reset(stream);
            self.drive_stream(state, peer, stream_id);
            return;
        };
        if inbound.closed {
            self.queue_protocol_reset(stream);
        } else if offset < inbound.next_offset {
            self.queue_credit(stream, dir);
        } else {
            let end = offset.saturating_add(bytes.len() as u64);
            if offset != inbound.next_offset || end > inbound.max_offset {
                self.queue_protocol_reset(stream);
            } else {
                let written = inbound.pipe.try_write(&bytes);
                match written {
                    Ok(n) if n == bytes.len() => {
                        inbound.next_offset = end;
                        self.queue_credit(stream, dir);
                    }
                    Ok(_) => {
                        self.queue_protocol_reset(stream);
                    }
                    Err(_) => {
                        inbound.closed = true;
                        stream
                            .control_mut()
                            .pending
                            .set_reset(reset_target_for_dir(dir), ResetCode::Cancelled);
                    }
                }
            }
        }
        *stream.last_activity_mut() = Instant::now();
        self.drive_stream(state, peer, stream_id);
    }

    fn handle_stream_credit(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        stream_id: StreamId,
        dir: Direction,
        recv_offset: u64,
        max_offset: u64,
    ) {
        let key = (peer, stream_id);
        let Some(stream) = state.streams.get_mut(&key) else {
            return;
        };
        self.note_setup_seen_from_remote(stream);
        let Some(outbound) = stream.outbound_mut(dir) else {
            self.queue_protocol_reset(stream);
            self.drive_stream(state, peer, stream_id);
            return;
        };
        let released_offset = outbound.pipe.released_offset();
        let sent_offset = outbound.pipe.sent_offset();
        if recv_offset < released_offset || recv_offset > sent_offset || max_offset < recv_offset {
            self.queue_protocol_reset(stream);
        } else {
            outbound.pipe.release_to(recv_offset);
            outbound.remote_max_offset = outbound.remote_max_offset.max(max_offset);
            if matches!(
                stream.control().awaiting.as_ref().map(|awaiting| &awaiting.frame),
                Some(AwaitingFrame::Data { offset, len, .. })
                    if recv_offset >= offset.saturating_add(*len as u64)
            ) {
                stream.control_mut().awaiting = None;
            }
        }
        *stream.last_activity_mut() = Instant::now();
        self.drive_stream(state, peer, stream_id);
    }

    fn handle_stream_finish(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        stream_id: StreamId,
        dir: Direction,
    ) {
        let key = (peer, stream_id);
        let Some(stream) = state.streams.get_mut(&key) else {
            return;
        };
        self.note_setup_seen_from_remote(stream);
        let Some(inbound) = stream.inbound_mut(dir) else {
            self.queue_protocol_reset(stream);
            self.drive_stream(state, peer, stream_id);
            return;
        };
        if !inbound.closed {
            inbound.closed = true;
            inbound.pipe.finish();
        }
        *stream.last_activity_mut() = Instant::now();
        self.maybe_reap_stream(state, peer, stream_id);
    }

    fn handle_stream_reset(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        stream_id: StreamId,
        dir: stream::ResetTarget,
        code: ResetCode,
    ) {
        let key = (peer, stream_id);
        let Some(stream) = state.streams.get_mut(&key) else {
            return;
        };
        self.note_setup_seen_from_remote(stream);
        self.apply_remote_reset(stream, stream_id, dir, code);
        *stream.last_activity_mut() = Instant::now();
        self.maybe_reap_stream(state, peer, stream_id);
    }

    fn process_packet_ack(&self, state: &mut RuntimeState, peer: XID, packet_id: PacketId) {
        let key = state.streams.iter().find_map(|(key, stream)| {
            (key.0 == peer
                && stream
                    .control()
                    .awaiting
                    .as_ref()
                    .is_some_and(|awaiting| awaiting.packet_id == packet_id))
            .then_some(*key)
        });
        let Some(key) = key else {
            return;
        };
        let Some(stream) = state.streams.get_mut(&key) else {
            return;
        };
        let Some(awaiting) = stream.control_mut().awaiting.take() else {
            return;
        };

        let mut reap = false;
        match awaiting.frame {
            AwaitingFrame::Control(StreamFrame::Open(_)) => {
                if let StreamState::Initiator(stream) = stream {
                    if let InitiatorAccept::Opening {
                        accept_waiter,
                        open_timeout_token,
                    } = &mut stream.accept
                    {
                        let waiter = accept_waiter.take();
                        let token = *open_timeout_token;
                        stream.accept = InitiatorAccept::WaitingAccept {
                            accept_waiter: waiter,
                            open_timeout_token: token,
                        };
                    }
                }
            }
            AwaitingFrame::Control(StreamFrame::Accept(_)) => {
                if let StreamState::Responder(stream) = stream {
                    if let ResponderResponse::Accepted { body, .. } = &mut stream.response {
                        body.data_enabled = true;
                    }
                }
            }
            AwaitingFrame::Control(StreamFrame::Reject(_)) => {
                reap = true;
            }
            AwaitingFrame::Control(StreamFrame::Finish(_)) => {
                if let Some(outbound) = stream.outbound_mut(Direction::Request) {
                    outbound.pipe.close();
                }
                if let Some(outbound) = stream.outbound_mut(Direction::Response) {
                    outbound.pipe.close();
                }
            }
            AwaitingFrame::Control(StreamFrame::Reset(StreamFrameReset { dir, .. })) => {
                for outbound_dir in [Direction::Request, Direction::Response] {
                    let affects_outbound = match (dir, outbound_dir) {
                        (stream::ResetTarget::Request, Direction::Request)
                        | (stream::ResetTarget::Response, Direction::Response)
                        | (stream::ResetTarget::Both, _) => true,
                        _ => false,
                    };
                    if affects_outbound {
                        if let Some(outbound) = stream.outbound_mut(outbound_dir) {
                            outbound.pipe.close();
                        }
                    }
                }
            }
            AwaitingFrame::Control(StreamFrame::Data(_) | StreamFrame::Credit(_)) => {}
            AwaitingFrame::Data { .. } => {}
        }

        if reap {
            self.maybe_reap_stream(state, key.0, key.1);
        } else {
            self.drive_stream(state, key.0, key.1);
        }
    }

    fn drive_streams(&self, state: &mut RuntimeState) {
        let keys: Vec<_> = state.streams.keys().copied().collect();
        for (peer, stream_id) in keys {
            self.drive_stream(state, peer, stream_id);
        }
    }

    fn drive_stream(&self, state: &mut RuntimeState, peer: XID, stream_id: StreamId) {
        let (streams, core) = (&mut state.streams, &mut state.core);
        let Some(stream) = streams.get_mut(&(peer, stream_id)) else {
            return;
        };
        match stream {
            StreamState::Initiator(stream) => {
                self.drive_outbound(core, stream.meta.key, &mut stream.control, Some(&mut stream.request));
            }
            StreamState::Responder(stream) => {
                let key = stream.meta.key;
                match &mut stream.response {
                    ResponderResponse::Accepted { body, .. } => {
                        self.drive_outbound(core, key, &mut stream.control, Some(body));
                    }
                    _ => self.drive_outbound(core, key, &mut stream.control, None),
                }
            }
        }
    }

    fn drive_outbound(
        &self,
        core: &mut CoreState,
        key: crate::runtime::internal::StreamKey,
        control: &mut StreamControl,
        outbound: Option<&mut OutboundBody>,
    ) {
        let stream_id = key.stream_id;
        let mut next_control = None;
        let mut next_data = None;
        if control.awaiting.is_none() {
            if let Some(frame) = control.pending.take_next_control(stream_id) {
                next_control = Some(frame);
            } else if let Some(outbound) = outbound {
                if outbound.data_enabled && !outbound.closed {
                    if let Some(mut send) = outbound
                        .pipe
                        .reserve_send(outbound.remote_max_offset, self.config.max_payload_bytes)
                    {
                        let mut bytes = vec![0; send.len()];
                        send.read_exact(&mut bytes).expect("grant length is exact");
                        next_data = Some((outbound.dir, send.offset(), bytes));
                    } else if outbound.pipe.writer_finished() && outbound.pipe.all_sent() {
                        outbound.closed = true;
                        next_control = Some(StreamFrame::Finish(StreamFrameFinish {
                            stream_id,
                            dir: outbound.dir,
                        }));
                    }
                }
            }
        }

        if let Some(frame) = next_control {
            self.send_control_frame(core, key, control, frame, 0);
        } else if let Some((dir, offset, bytes)) = next_data {
            self.send_data_frame(core, key, control, dir, offset, bytes, 0);
        }
    }

    fn send_control_frame(
        &self,
        core: &mut CoreState,
        key: crate::runtime::internal::StreamKey,
        control: &mut StreamControl,
        frame: StreamFrame,
        attempt: u8,
    ) {
        let packet_id = core.next_packet_id();
        control.awaiting = Some(AwaitingPacket {
            packet_id,
            frame: AwaitingFrame::Control(frame.clone()),
            attempt,
        });
        let valid_until = now_secs().saturating_add(self.config.packet_expiration.as_secs());
        self.enqueue_stream_body(
            core,
            key.peer,
            Some(key.stream_id),
            Some(packet_id),
            true,
            false,
            StreamBody {
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
        key: crate::runtime::internal::StreamKey,
        control: &mut StreamControl,
        dir: Direction,
        offset: u64,
        bytes: Vec<u8>,
        attempt: u8,
    ) {
        let packet_id = core.next_packet_id();
        control.awaiting = Some(AwaitingPacket {
            packet_id,
            frame: AwaitingFrame::Data {
                dir,
                offset,
                len: bytes.len(),
            },
            attempt,
        });
        let valid_until = now_secs().saturating_add(self.config.packet_expiration.as_secs());
        self.enqueue_stream_body(
            core,
            key.peer,
            Some(key.stream_id),
            Some(packet_id),
            true,
            false,
            StreamBody {
                packet_id,
                valid_until,
                packet_ack: None,
                frame: Some(StreamFrame::Data(StreamFrameData {
                    stream_id: key.stream_id,
                    dir,
                    offset,
                    bytes,
                })),
            },
        );
    }

    fn queue_credit(&self, stream: &mut StreamState, dir: Direction) {
        let stream_id = stream.key().stream_id;
        let (recv_offset, max_offset) = {
            let Some(inbound) = stream.inbound_mut(dir) else {
                return;
            };
            (inbound.next_offset, inbound.max_offset)
        };
        stream.control_mut().pending.set_credit(StreamFrameCredit {
            stream_id,
            dir,
            recv_offset,
            max_offset,
        });
    }

    fn queue_protocol_reset(&self, stream: &mut StreamState) {
        let id = stream.key().stream_id;
        stream
            .control_mut()
            .pending
            .set_reset(stream::ResetTarget::Both, ResetCode::Protocol);
        for dir in [Direction::Request, Direction::Response] {
            if let Some(outbound) = stream.outbound_mut(dir) {
                outbound.closed = true;
                outbound.pipe.close();
            }
            if let Some(inbound) = stream.inbound_mut(dir) {
                if !inbound.closed {
                    inbound.closed = true;
                    inbound.pipe.fail(QlError::StreamProtocol { id });
                }
            }
        }
        if let StreamState::Initiator(stream) = stream {
            match &mut stream.accept {
                InitiatorAccept::Opening { accept_waiter, .. }
                | InitiatorAccept::WaitingAccept { accept_waiter, .. } => {
                    if let Some(mut waiter) = accept_waiter.take() {
                        if let Some(tx) = waiter.tx.take() {
                            let _ = tx.send(Err(QlError::StreamProtocol { id }));
                        }
                    }
                }
                InitiatorAccept::Open { .. } => {}
            }
        }
    }

    fn note_setup_seen_from_remote(&self, stream: &mut StreamState) {
        if let StreamState::Responder(stream) = stream {
            if matches!(
                stream
                    .control
                    .awaiting
                    .as_ref()
                    .map(|awaiting| &awaiting.frame),
                Some(AwaitingFrame::Control(StreamFrame::Accept(_)))
            ) {
                stream.control.awaiting = None;
                if let ResponderResponse::Accepted { body, .. } = &mut stream.response {
                    body.data_enabled = true;
                }
            }
            if matches!(
                stream
                    .control
                    .awaiting
                    .as_ref()
                    .map(|awaiting| &awaiting.frame),
                Some(AwaitingFrame::Control(StreamFrame::Reject(_)))
            ) {
                stream.control.awaiting = None;
            }
        }
    }

    fn apply_remote_reset(
        &self,
        stream: &mut StreamState,
        stream_id: StreamId,
        dir: stream::ResetTarget,
        code: ResetCode,
    ) {
        let request_error = QlError::StreamReset {
            id: stream_id,
            dir: Direction::Request,
            code,
        };
        let response_error = QlError::StreamReset {
            id: stream_id,
            dir: Direction::Response,
            code,
        };

        if matches!(
            dir,
            stream::ResetTarget::Request | stream::ResetTarget::Both
        ) {
            if let Some(inbound) = stream.inbound_mut(Direction::Request) {
                if !inbound.closed {
                    inbound.closed = true;
                    inbound.pipe.fail(request_error.clone());
                }
            }
            if let Some(outbound) = stream.outbound_mut(Direction::Request) {
                outbound.closed = true;
                outbound.pipe.close();
            }
        }
        if matches!(
            dir,
            stream::ResetTarget::Response | stream::ResetTarget::Both
        ) {
            if let Some(inbound) = stream.inbound_mut(Direction::Response) {
                if !inbound.closed {
                    inbound.closed = true;
                    inbound.pipe.fail(response_error.clone());
                }
            }
            if let Some(outbound) = stream.outbound_mut(Direction::Response) {
                outbound.closed = true;
                outbound.pipe.close();
            }
        }

        if let StreamState::Initiator(stream) = stream {
            match &mut stream.accept {
                InitiatorAccept::Opening { accept_waiter, .. }
                | InitiatorAccept::WaitingAccept { accept_waiter, .. } => {
                    if let Some(mut waiter) = accept_waiter.take() {
                        if let Some(tx) = waiter.tx.take() {
                            let _ = tx.send(Err(match dir {
                                stream::ResetTarget::Request => request_error,
                                _ => response_error,
                            }));
                        }
                    }
                }
                InitiatorAccept::Open { .. } => {}
            }
        }
    }

    fn maybe_reap_stream(&self, state: &mut RuntimeState, peer: XID, stream_id: StreamId) {
        if state
            .streams
            .get(&(peer, stream_id))
            .is_some_and(StreamState::can_reap)
        {
            state.streams.remove(&(peer, stream_id));
        }
    }

    fn stream_matches_open(
        &self,
        stream: &StreamState,
        route_id: RouteId,
        request_head: &[u8],
        response_max_offset: u64,
    ) -> bool {
        match stream {
            StreamState::Responder(state) => match &state.response {
                ResponderResponse::Pending { initial_credit } => {
                    state.meta.route_id == route_id
                        && state.meta.request_head == request_head
                        && *initial_credit == response_max_offset
                }
                ResponderResponse::Accepted { initial_credit, .. }
                | ResponderResponse::Rejecting { initial_credit, .. } => {
                    state.meta.route_id == route_id
                        && state.meta.request_head == request_head
                        && *initial_credit == response_max_offset
                }
            },
            _ => false,
        }
    }

    fn send_packet_ack(&self, core: &mut CoreState, peer: XID, acked_packet: PacketId) {
        let packet_id = core.next_packet_id();
        let valid_until = now_secs().saturating_add(self.config.packet_expiration.as_secs());
        self.enqueue_stream_body(
            core,
            peer,
            None,
            None,
            false,
            true,
            StreamBody {
                packet_id,
                valid_until,
                packet_ack: Some(stream::PacketAck {
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
        stream_id: StreamId,
        dir: stream::ResetTarget,
        code: ResetCode,
    ) {
        let packet_id = core.next_packet_id();
        let valid_until = now_secs().saturating_add(self.config.packet_expiration.as_secs());
        self.enqueue_stream_body(
            core,
            peer,
            None,
            None,
            false,
            true,
            StreamBody {
                packet_id,
                valid_until,
                packet_ack: None,
                frame: Some(StreamFrame::Reset(StreamFrameReset {
                    stream_id,
                    dir,
                    code,
                })),
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
            stream_id: None,
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

    fn enqueue_stream_body(
        &self,
        core: &mut CoreState,
        peer: XID,
        stream_id: Option<StreamId>,
        packet_id: Option<PacketId>,
        track_ack: bool,
        priority: bool,
        body: StreamBody,
    ) {
        let token = core.next_token();
        let message = OutboundMessage {
            peer,
            token,
            stream_id,
            packet_id,
            track_ack,
            payload: OutboundPayload::DeferredStream(body),
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

    fn record_stream_activity(&self, state: &mut RuntimeState, peer: XID, stream_id: StreamId) {
        if let Some(stream) = state.streams.get_mut(&(peer, stream_id)) {
            *stream.last_activity_mut() = Instant::now();
        }
    }

    fn persist_peers(&self, state: &RuntimeState) {
        self.platform.persist_peers(state.core.peers.all());
    }

    fn drop_outbound_for_peer(&self, state: &mut RuntimeState, peer: XID) {
        let stream_ids: Vec<_> = state
            .core
            .outbound
            .iter()
            .filter(|message| message.peer == peer)
            .filter_map(|message| message.stream_id)
            .collect();
        state.core.outbound.retain(|message| message.peer != peer);
        for stream_id in stream_ids {
            self.fail_stream(state, peer, stream_id, QlError::SendFailed);
        }
    }

    fn abort_streams_for_peer(&self, state: &mut RuntimeState, peer: XID, error: QlError) {
        let keys: Vec<_> = state
            .streams
            .keys()
            .copied()
            .filter(|(stream_peer, _)| *stream_peer == peer)
            .collect();
        for (_, stream_id) in keys {
            self.fail_stream(state, peer, stream_id, error.clone());
        }
    }

    fn fail_stream(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        stream_id: StreamId,
        error: QlError,
    ) {
        let Some(mut stream) = state.streams.remove(&(peer, stream_id)) else {
            return;
        };
        if let StreamState::Initiator(stream) = &mut stream {
            match &mut stream.accept {
                InitiatorAccept::Opening { accept_waiter, .. }
                | InitiatorAccept::WaitingAccept { accept_waiter, .. } => {
                    if let Some(mut waiter) = accept_waiter.take() {
                        if let Some(tx) = waiter.tx.take() {
                            let _ = tx.send(Err(error.clone()));
                        }
                    }
                }
                InitiatorAccept::Open { .. } => {}
            }
        }
        for dir in [Direction::Request, Direction::Response] {
            if let Some(outbound) = stream.outbound_mut(dir) {
                outbound.closed = true;
                outbound.pipe.close();
            }
            if let Some(inbound) = stream.inbound_mut(dir) {
                if !inbound.closed {
                    inbound.closed = true;
                    inbound.pipe.fail(error.clone());
                }
            }
        }
    }

    fn unpair_peer(&self, state: &mut RuntimeState, peer: XID) {
        if state.core.peers.remove_peer(peer).is_none() {
            return;
        }
        self.drop_outbound_for_peer(state, peer);
        self.abort_streams_for_peer(state, peer, QlError::SendFailed);
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
                    let mut timed_out_stream = None;
                    state.core.outbound.retain(|message| {
                        if message.token == token {
                            timed_out_stream =
                                message.stream_id.map(|stream_id| (message.peer, stream_id));
                            false
                        } else {
                            true
                        }
                    });
                    if let Some((peer, stream_id)) = timed_out_stream {
                        self.fail_stream(state, peer, stream_id, QlError::SendFailed);
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
                        self.abort_streams_for_peer(state, peer, QlError::SendFailed);
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
                        self.abort_streams_for_peer(state, peer, QlError::SendFailed);
                    }
                }
                TimeoutKind::StreamOpen {
                    peer,
                    stream_id,
                    token,
                } => {
                    let should_fail = state
                        .streams
                        .get(&(peer, stream_id))
                        .and_then(StreamState::open_timeout_token)
                        .is_some_and(|stream_token| stream_token == token);
                    if should_fail {
                        self.fail_stream(state, peer, stream_id, QlError::Timeout);
                    }
                }
                TimeoutKind::StreamPacket {
                    peer,
                    stream_id,
                    packet_id,
                    attempt,
                } => {
                    let key = (peer, stream_id);
                    let mut timed_out = false;
                    enum Retransmit {
                        Control(StreamFrame),
                        Data {
                            dir: Direction,
                            offset: u64,
                            len: usize,
                        },
                    }
                    {
                        let (streams, core) = (&mut state.streams, &mut state.core);
                        let Some(stream) = streams.get_mut(&key) else {
                            continue;
                        };
                        let Some(retransmit) =
                            stream.control().awaiting.as_ref().and_then(|awaiting| {
                                if awaiting.packet_id != packet_id || awaiting.attempt != attempt {
                                    return None;
                                }
                                Some(match &awaiting.frame {
                                    AwaitingFrame::Control(frame) => {
                                        Retransmit::Control(frame.clone())
                                    }
                                    AwaitingFrame::Data { dir, offset, len } => Retransmit::Data {
                                        dir: *dir,
                                        offset: *offset,
                                        len: *len,
                                    },
                                })
                            })
                        else {
                            continue;
                        };
                        if attempt >= self.config.stream_retry_limit {
                            timed_out = true;
                        } else {
                            match retransmit {
                                Retransmit::Control(frame) => {
                                    let key = stream.key();
                                    self.send_control_frame(
                                        core,
                                        key,
                                        stream.control_mut(),
                                        frame,
                                        attempt.saturating_add(1),
                                    );
                                }
                                Retransmit::Data { dir, offset, len } => {
                                    let key = stream.key();
                                    let Some(bytes) = (match stream.outbound_mut(dir) {
                                        Some(outbound) => match outbound.pipe.retry_send(offset, len) {
                                            Some(mut grant) => {
                                                let mut bytes = vec![0; grant.len()];
                                                grant
                                                    .read_exact(&mut bytes)
                                                    .expect("grant length is exact");
                                                Some(bytes)
                                            }
                                            None => None,
                                        },
                                        None => None,
                                    }) else {
                                        continue;
                                    };
                                    self.send_data_frame(
                                        core,
                                        key,
                                        stream.control_mut(),
                                        dir,
                                        offset,
                                        bytes,
                                        attempt.saturating_add(1),
                                    );
                                }
                            }
                        }
                    }
                    if timed_out {
                        self.fail_stream(state, peer, stream_id, QlError::Timeout);
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
        stream_id: Option<StreamId>,
        packet_id: Option<PacketId>,
        track_ack: bool,
        result: Result<(), QlError>,
    ) {
        if result.is_err() {
            if let Some(stream_id) = stream_id {
                self.fail_stream(state, peer, stream_id, QlError::SendFailed);
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
                self.abort_streams_for_peer(state, peer, QlError::SendFailed);
            }
            return;
        }

        if track_ack {
            if let (Some(stream_id), Some(packet_id)) = (stream_id, packet_id) {
                let attempt = state
                    .streams
                    .get(&(peer, stream_id))
                    .and_then(|stream| stream.control().awaiting.as_ref())
                    .and_then(|awaiting| {
                        (awaiting.packet_id == packet_id).then_some(awaiting.attempt)
                    })
                    .unwrap_or(0);
                state.core.timeouts.push(Reverse(TimeoutEntry {
                    at: Instant::now() + self.config.packet_ack_timeout,
                    kind: TimeoutKind::StreamPacket {
                        peer,
                        stream_id,
                        packet_id,
                        attempt,
                    },
                }));
            }
        }
    }
}

fn reset_target_for_dir(dir: Direction) -> stream::ResetTarget {
    match dir {
        Direction::Request => stream::ResetTarget::Request,
        Direction::Response => stream::ResetTarget::Response,
    }
}
