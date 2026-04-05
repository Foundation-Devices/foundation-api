use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    task::{Context, Poll, Waker},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use futures_lite::future::poll_fn;
use ql_fsm::{FsmTime, QlFsm, QlFsmEvent, SessionWriteId};
use ql_wire::{CloseTarget, StreamCloseCode, StreamId, XID};

use crate::{
    command::RuntimeCommand,
    handle::{ByteReader, ByteWriter, InboundStream},
    platform::{PlatformFuture, QlPlatform},
    InboundEvent, OpenedStreamDelivery, QlError, Runtime,
};

struct InFlightWrite<'a> {
    session_write_id: Option<SessionWriteId>,
    future: PlatformFuture<'a, Result<(), QlError>>,
}

enum DriverEvent {
    Command(RuntimeCommand),
    WriteCompleted {
        index: usize,
        result: Result<(), QlError>,
    },
    TimerExpired,
    CommandsClosed,
}

enum OutboundIo {
    Open {
        reader: piper::Reader,
        finish_queued: bool,
    },
    Closed,
}

impl OutboundIo {
    fn new(reader: piper::Reader) -> Self {
        Self::Open {
            reader,
            finish_queued: false,
        }
    }

    fn close(&mut self) {
        *self = Self::Closed;
    }

    fn open_mut(&mut self) -> Option<(&mut piper::Reader, &mut bool)> {
        match self {
            Self::Open {
                reader,
                finish_queued,
            } => Some((reader, finish_queued)),
            Self::Closed => None,
        }
    }
}

enum InboundIo {
    Open(async_channel::Sender<InboundEvent>),
    Closed,
}

impl InboundIo {
    fn new(tx: async_channel::Sender<InboundEvent>) -> Self {
        Self::Open(tx)
    }

    fn close(&mut self) {
        if let Self::Open(tx) = self {
            tx.close();
        }
        *self = Self::Closed;
    }

    fn write_or_close(&mut self, bytes: Vec<u8>) -> bool {
        let Self::Open(tx) = self else {
            return true;
        };

        if tx.try_send(InboundEvent::Data(bytes)).is_err() {
            tx.close();
            *self = Self::Closed;
            return true;
        }

        false
    }

    fn finish(&mut self) {
        if let Self::Open(tx) = self {
            let _ = tx.try_send(InboundEvent::Finished);
            tx.close();
        }
        *self = Self::Closed;
    }

    fn fail(&mut self, error: QlError) {
        if let Self::Open(tx) = self {
            let _ = tx.try_send(InboundEvent::Failed(error));
            tx.close();
        }
        *self = Self::Closed;
    }
}

enum DriverStreamIo {
    Initiator {
        request: OutboundIo,
        response: InboundIo,
    },
    Responder {
        request: InboundIo,
        response: OutboundIo,
    },
}

impl DriverStreamIo {
    fn new_initiator(
        request: piper::Reader,
        response: async_channel::Sender<InboundEvent>,
    ) -> Self {
        Self::Initiator {
            request: OutboundIo::new(request),
            response: InboundIo::new(response),
        }
    }

    fn new_responder(
        request: async_channel::Sender<InboundEvent>,
        response: piper::Reader,
    ) -> Self {
        Self::Responder {
            request: InboundIo::new(request),
            response: OutboundIo::new(response),
        }
    }

    fn outbound_mut(&mut self) -> &mut OutboundIo {
        match self {
            Self::Initiator { request, .. } => request,
            Self::Responder { response, .. } => response,
        }
    }

    fn inbound_mut(&mut self) -> &mut InboundIo {
        match self {
            Self::Initiator { response, .. } => response,
            Self::Responder { request, .. } => request,
        }
    }

    fn inbound_target(&self) -> CloseTarget {
        match self {
            Self::Initiator { .. } => CloseTarget::Return,
            Self::Responder { .. } => CloseTarget::Origin,
        }
    }

    fn outbound_target(&self) -> CloseTarget {
        match self {
            Self::Initiator { .. } => CloseTarget::Origin,
            Self::Responder { .. } => CloseTarget::Return,
        }
    }

    fn fail_all(&mut self, error: QlError) {
        match self {
            Self::Initiator {
                request, response, ..
            } => {
                request.close();
                response.fail(error);
            }
            Self::Responder {
                request, response, ..
            } => {
                request.fail(error);
                response.close();
            }
        }
    }
}

struct DriverState {
    streams: HashMap<StreamId, DriverStreamIo>,
    runtime_tx: async_channel::Sender<RuntimeCommand>,
    stream_send_buffer_bytes: usize,
    max_concurrent_message_writes: usize,
    peer_xid: Option<XID>,
    pending_fsm_events: VecDeque<QlFsmEvent>,
}

impl DriverState {
    fn drive_command<'a, P: QlPlatform>(
        &mut self,
        fsm: &mut QlFsm,
        command: RuntimeCommand,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<'a>>,
    ) {
        match command {
            RuntimeCommand::BindPeer { peer } => {
                self.peer_xid = Some(peer.xid);
                fsm.bind_peer(peer);
                self.finish_step(fsm, platform, in_flight);
            }
            RuntimeCommand::Connect => {
                let _ = self.with_fsm_events(fsm, platform, |fsm, emit| {
                    fsm.connect_ik(now(), platform, emit)
                });
                self.finish_step(fsm, platform, in_flight);
            }
            RuntimeCommand::Incoming(bytes) => {
                let _ = self.with_fsm_events(fsm, platform, |fsm, emit| {
                    fsm.receive(now(), bytes, platform, emit)
                });
                self.finish_step(fsm, platform, in_flight);
            }
            RuntimeCommand::OpenStream {
                request_reader,
                start,
            } => match fsm.open_stream().map_err(QlError::from) {
                Ok(stream_id) => {
                    let (response_tx, response_rx) = async_channel::unbounded();
                    self.streams.insert(
                        stream_id,
                        DriverStreamIo::new_initiator(request_reader, response_tx),
                    );
                    let _ = start.send(Ok(OpenedStreamDelivery {
                        stream_id,
                        response: response_rx,
                    }));
                    self.poll_stream(fsm, stream_id);
                    self.finish_step(fsm, platform, in_flight);
                }
                Err(error) => {
                    let _ = start.send(Err(error));
                }
            },
            RuntimeCommand::PollStream { stream_id } => {
                self.poll_stream(fsm, stream_id);
                self.finish_step(fsm, platform, in_flight);
            }
            RuntimeCommand::CloseStream {
                stream_id,
                target,
                code,
            } => {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    if target == CloseTarget::Both || target == stream.inbound_target() {
                        stream.inbound_mut().close();
                    }
                    if target == CloseTarget::Both || target == stream.outbound_target() {
                        stream.outbound_mut().close();
                    }
                }
                let _ = fsm.close_stream(stream_id, target, code);
                self.try_reap_stream(stream_id);
                self.finish_step(fsm, platform, in_flight);
            }
        }
    }

    fn drive_write_completed<'a, P: QlPlatform>(
        &mut self,
        fsm: &mut QlFsm,
        session_write_id: Option<SessionWriteId>,
        result: Result<(), QlError>,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<'a>>,
    ) {
        if let Some(write_id) = session_write_id {
            match result {
                Ok(()) => fsm.confirm_session_write(now(), write_id),
                Err(_) => fsm.reject_session_write(write_id),
            }
        }
        self.finish_step(fsm, platform, in_flight);
    }

    fn finish_step<'a, P: QlPlatform>(
        &mut self,
        fsm: &mut QlFsm,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<'a>>,
    ) {
        while self.fill_write_slots(fsm, platform, in_flight) {}
    }

    fn with_fsm_events<P: QlPlatform, T>(
        &mut self,
        fsm: &mut QlFsm,
        platform: &P,
        run: impl FnOnce(&mut QlFsm, &mut dyn FnMut(QlFsmEvent)) -> T,
    ) -> T {
        let output = {
            let pending = &mut self.pending_fsm_events;
            let mut emit = |event| pending.push_back(event);
            run(fsm, &mut emit)
        };
        self.process_pending_fsm_events(fsm, platform);
        output
    }

    fn process_pending_fsm_events<P: QlPlatform>(&mut self, fsm: &mut QlFsm, platform: &P) {
        while let Some(event) = self.pending_fsm_events.pop_front() {
            self.process_fsm_event(fsm, platform, event);
        }
    }

    fn process_fsm_event<P: QlPlatform>(
        &mut self,
        fsm: &mut QlFsm,
        platform: &P,
        event: QlFsmEvent,
    ) {
        match event {
            QlFsmEvent::NewPeer => {
                if let Some(peer) = fsm.peer().cloned() {
                    self.peer_xid = Some(peer.xid);
                    platform.persist_peer(peer);
                }
            }
            QlFsmEvent::PeerStatusChanged(status) => {
                if self.peer_xid.is_none() {
                    self.peer_xid = fsm.peer().map(|peer| peer.xid);
                }
                if let Some(peer) = self.peer_xid {
                    platform.handle_peer_status(peer, status);
                }
            }
            QlFsmEvent::Opened(stream_id) => {
                self.handle_opened_stream(platform, stream_id);
            }
            QlFsmEvent::Readable(stream_id) => {
                self.handle_inbound_readable(fsm, stream_id);
            }
            QlFsmEvent::Writable(stream_id) => {
                self.poll_stream(fsm, stream_id);
            }
            QlFsmEvent::Finished(stream_id) => {
                self.handle_inbound_finished(stream_id);
            }
            QlFsmEvent::Closed(frame) => {
                self.handle_closed_stream(frame);
            }
            QlFsmEvent::WritableClosed(stream_id) => {
                self.handle_writable_closed(stream_id);
            }
            QlFsmEvent::SessionClosed(_) => self.fail_all_streams(QlError::SessionClosed),
        }
    }

    fn handle_opened_stream<P: QlPlatform>(&mut self, platform: &P, stream_id: StreamId) {
        let (request_tx, request_rx) = async_channel::unbounded();
        let (response_reader, response_writer) = piper::pipe(self.stream_send_buffer_bytes);

        self.streams.insert(
            stream_id,
            DriverStreamIo::new_responder(request_tx, response_reader),
        );

        platform.handle_inbound(InboundStream {
            stream_id,
            request: ByteReader::new(
                stream_id,
                CloseTarget::Origin,
                request_rx,
                self.runtime_tx.clone(),
            ),
            response: ByteWriter::new(
                stream_id,
                CloseTarget::Return,
                response_writer,
                self.runtime_tx.clone(),
            ),
        });
    }

    fn handle_inbound_readable(&mut self, fsm: &mut QlFsm, stream_id: StreamId) {
        loop {
            let Some(available) = fsm.stream_available_bytes(stream_id) else {
                return;
            };
            if available == 0 {
                break;
            }

            let bytes = {
                let Some(chunks) = fsm.stream_read(stream_id) else {
                    return;
                };
                let mut bytes = Vec::with_capacity(available);
                for chunk in chunks {
                    bytes.extend_from_slice(chunk);
                }
                bytes
            };

            if bytes.is_empty() {
                break;
            }

            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return;
            };
            let target = stream.inbound_target();
            if stream.inbound_mut().write_or_close(bytes.clone()) {
                let _ = fsm.close_stream(stream_id, target, StreamCloseCode(0));
                self.try_reap_stream(stream_id);
                break;
            }
            fsm.stream_read_commit(stream_id, bytes.len()).unwrap();
        }
    }

    fn handle_inbound_finished(&mut self, stream_id: StreamId) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        stream.inbound_mut().finish();
        self.try_reap_stream(stream_id);
    }

    fn handle_closed_stream(&mut self, frame: ql_wire::StreamClose) {
        let Some(stream) = self.streams.get_mut(&frame.stream_id) else {
            return;
        };

        let error = QlError::StreamClosed {
            target: frame.target,
            code: frame.code,
        };

        if frame.target == CloseTarget::Both || frame.target == stream.inbound_target() {
            stream.inbound_mut().fail(error.clone());
        }
        if frame.target == CloseTarget::Both || frame.target == stream.outbound_target() {
            stream.outbound_mut().close();
        }
        self.try_reap_stream(frame.stream_id);
    }

    fn handle_writable_closed(&mut self, stream_id: StreamId) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        stream.outbound_mut().close();
        self.try_reap_stream(stream_id);
    }

    fn fail_all_streams(&mut self, error: QlError) {
        for stream in self.streams.values_mut() {
            stream.fail_all(error.clone());
        }
        self.streams.clear();
    }

    fn fill_write_slots<'a, P: QlPlatform>(
        &mut self,
        fsm: &mut QlFsm,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<'a>>,
    ) -> bool {
        let mut progressed = false;

        while in_flight.len() < self.max_concurrent_message_writes {
            let Some(write) = fsm.take_next_write(now(), platform) else {
                break;
            };
            progressed = true;
            in_flight.push(InFlightWrite {
                session_write_id: write.session_write_id,
                future: platform.write_message(write.record),
            });
        }

        progressed
    }

    fn poll_stream(&mut self, fsm: &mut QlFsm, stream_id: StreamId) {
        loop {
            let mut should_finish = false;
            let progressed = {
                let Some(stream) = self.streams.get_mut(&stream_id) else {
                    return;
                };
                let Some((reader, finish_queued)) = stream.outbound_mut().open_mut() else {
                    return;
                };

                let ready = with_noop_context(|cx| reader.poll(cx));
                if matches!(ready, Poll::Pending) {
                    false
                } else {
                    let bytes = reader.peek_buf();
                    if bytes.is_empty() {
                        if reader.is_closed() && reader.len() == 0 && !*finish_queued {
                            *finish_queued = true;
                            should_finish = true;
                        }
                        false
                    } else {
                        let len = bytes.len();
                        let accepted = match fsm.write_stream(stream_id, bytes) {
                            Ok(accepted) => accepted,
                            Err(_) => 0,
                        };
                        if accepted > 0 {
                            reader.consume(accepted);
                        }
                        accepted > 0 && accepted == len
                    }
                }
            };

            if should_finish {
                let _ = fsm.finish_stream(stream_id);
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.outbound_mut().close();
                }
                self.try_reap_stream(stream_id);
                break;
            }

            if !progressed {
                break;
            }
        }
    }

    fn try_reap_stream(&mut self, stream_id: StreamId) {
        let should_reap = self
            .streams
            .get(&stream_id)
            .is_some_and(|stream| match stream {
                DriverStreamIo::Initiator {
                    request, response, ..
                } => matches!(request, OutboundIo::Closed) && matches!(response, InboundIo::Closed),
                DriverStreamIo::Responder {
                    request, response, ..
                } => matches!(request, InboundIo::Closed) && matches!(response, OutboundIo::Closed),
            });
        if should_reap {
            self.streams.remove(&stream_id);
        }
    }
}

async fn next_driver_event<P: QlPlatform>(
    rx: &async_channel::Receiver<RuntimeCommand>,
    platform: &P,
    next_timer: Option<Instant>,
    in_flight: &mut [InFlightWrite<'_>],
) -> DriverEvent {
    let mut recv_future = (!rx.is_closed()).then(|| Box::pin(rx.recv()));
    let mut sleep_future = next_timer.map(|deadline| {
        let timeout = deadline.saturating_duration_since(Instant::now());
        platform.sleep(timeout)
    });

    poll_fn(|cx| {
        for (index, write) in in_flight.iter_mut().enumerate() {
            if let Poll::Ready(result) = write.future.as_mut().poll(cx) {
                return Poll::Ready(DriverEvent::WriteCompleted { index, result });
            }
        }

        if let Some(future) = sleep_future.as_mut() {
            if let Poll::Ready(()) = future.as_mut().poll(cx) {
                return Poll::Ready(DriverEvent::TimerExpired);
            }
        }

        if let Some(future) = recv_future.as_mut() {
            if let Poll::Ready(res) = future.as_mut().poll(cx) {
                return Poll::Ready(match res {
                    Ok(command) => DriverEvent::Command(command),
                    Err(_) => DriverEvent::CommandsClosed,
                });
            }
        }

        Poll::Pending
    })
    .await
}

impl<P: QlPlatform> Runtime<P> {
    pub async fn run(self) {
        let Runtime {
            identity,
            platform,
            config,
            rx,
            tx,
        } = self;

        let runtime_tx = tx.upgrade().expect("runtime tx");
        let mut fsm = QlFsm::new(config.fsm, identity, now());
        let mut peer_xid = None;
        if let Some(peer) = platform.load_peer().await {
            peer_xid = Some(peer.xid);
            fsm.bind_peer(peer);
        }

        let mut state = DriverState {
            streams: HashMap::new(),
            runtime_tx,
            stream_send_buffer_bytes: config.stream_send_buffer_bytes,
            max_concurrent_message_writes: config.max_concurrent_message_writes,
            peer_xid,
            pending_fsm_events: VecDeque::new(),
        };
        let mut in_flight = Vec::new();

        loop {
            state.finish_step(&mut fsm, &platform, &mut in_flight);

            if rx.is_closed() && in_flight.is_empty() {
                break;
            }

            match next_driver_event(&rx, &platform, fsm.next_deadline(), &mut in_flight).await {
                DriverEvent::Command(command) => {
                    state.drive_command(&mut fsm, command, &platform, &mut in_flight)
                }
                DriverEvent::WriteCompleted { index, result } => {
                    let write = in_flight.swap_remove(index);
                    state.drive_write_completed(
                        &mut fsm,
                        write.session_write_id,
                        result,
                        &platform,
                        &mut in_flight,
                    );
                }
                DriverEvent::TimerExpired => {
                    state.with_fsm_events(&mut fsm, &platform, |fsm, emit| {
                        fsm.on_timer(now(), emit)
                    });
                    state.finish_step(&mut fsm, &platform, &mut in_flight);
                }
                DriverEvent::CommandsClosed => {}
            }
        }
    }
}

fn now() -> FsmTime {
    FsmTime {
        instant: Instant::now(),
        unix_secs: unix_now_secs(),
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn with_noop_context<T>(f: impl FnOnce(&mut Context<'_>) -> T) -> T {
    let mut cx = Context::from_waker(Waker::noop());
    f(&mut cx)
}

#[cfg(test)]
mod tests {
    use ql_wire::{
        MlKemCiphertext, MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey, PeerBundle, QlAead, QlHash,
        QlKem, QlRandom, SessionKey, StreamClose, XID,
    };

    use super::*;
    use crate::tests::new_identity;

    struct NoopPlatform;

    impl QlRandom for NoopPlatform {
        fn fill_random_bytes(&self, data: &mut [u8]) {
            data.fill(0);
        }
    }

    impl QlHash for NoopPlatform {
        fn sha256(&self, _parts: &[&[u8]]) -> [u8; 32] {
            [0; 32]
        }
    }

    impl QlAead for NoopPlatform {
        fn aes256_gcm_encrypt(
            &self,
            _key: &SessionKey,
            _nonce: &ql_wire::Nonce,
            _aad: &[u8],
            _buffer: &mut [u8],
        ) -> [u8; ql_wire::ENCRYPTED_MESSAGE_AUTH_SIZE] {
            [0; ql_wire::ENCRYPTED_MESSAGE_AUTH_SIZE]
        }

        fn aes256_gcm_decrypt(
            &self,
            _key: &SessionKey,
            _nonce: &ql_wire::Nonce,
            _aad: &[u8],
            _buffer: &mut [u8],
            _auth_tag: &[u8; ql_wire::ENCRYPTED_MESSAGE_AUTH_SIZE],
        ) -> bool {
            false
        }
    }

    impl QlKem for NoopPlatform {
        fn mlkem_generate_keypair(&self) -> MlKemKeyPair {
            MlKemKeyPair {
                private: MlKemPrivateKey::new(Box::new([0; MlKemPrivateKey::SIZE])),
                public: MlKemPublicKey::new(Box::new([0; MlKemPublicKey::SIZE])),
            }
        }

        fn mlkem_encapsulate(&self, _public_key: &MlKemPublicKey) -> (MlKemCiphertext, SessionKey) {
            (
                MlKemCiphertext::new(Box::new([0; MlKemCiphertext::SIZE])),
                SessionKey::from_data([0; SessionKey::SIZE]),
            )
        }

        fn mlkem_decapsulate(
            &self,
            _private_key: &MlKemPrivateKey,
            _ciphertext: &MlKemCiphertext,
        ) -> SessionKey {
            SessionKey::from_data([0; SessionKey::SIZE])
        }
    }

    impl QlPlatform for NoopPlatform {
        fn write_message(&self, _message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>> {
            Box::pin(async { Ok(()) })
        }

        fn sleep(&self, _duration: Duration) -> PlatformFuture<'_, ()> {
            Box::pin(async {})
        }

        fn load_peer(&self) -> PlatformFuture<'_, Option<PeerBundle>> {
            Box::pin(async { None })
        }

        fn persist_peer(&self, _peer: PeerBundle) {}

        fn handle_peer_status(&self, _peer: XID, _status: ql_fsm::PeerStatus) {}

        fn handle_inbound(&self, _event: InboundStream) {}
    }

    fn new_driver_state() -> (DriverState, QlFsm) {
        let (runtime_tx, _runtime_rx) = async_channel::unbounded();
        (
            DriverState {
                streams: HashMap::new(),
                runtime_tx,
                stream_send_buffer_bytes: 16,
                max_concurrent_message_writes: 1,
                peer_xid: None,
                pending_fsm_events: VecDeque::new(),
            },
            QlFsm::new(ql_fsm::QlFsmConfig::default(), new_identity(7), now()),
        )
    }

    #[test]
    fn handle_inbound_finished_reaps_closed_initiator_stream() {
        let (mut state, _fsm) = new_driver_state();
        let stream_id = StreamId(1);
        let (response_tx, _response_rx) = async_channel::unbounded();

        state.streams.insert(
            stream_id,
            DriverStreamIo::Initiator {
                request: OutboundIo::Closed,
                response: InboundIo::new(response_tx),
            },
        );

        state.handle_inbound_finished(stream_id);

        assert!(!state.streams.contains_key(&stream_id));
    }

    #[test]
    fn handle_closed_stream_reaps_when_both_halves_close() {
        let (mut state, _fsm) = new_driver_state();
        let stream_id = StreamId(2);
        let (request_tx, _request_rx) = async_channel::unbounded();
        let (response_reader, _response_writer) = piper::pipe(1);

        state.streams.insert(
            stream_id,
            DriverStreamIo::Responder {
                request: InboundIo::new(request_tx),
                response: OutboundIo::new(response_reader),
            },
        );

        state.handle_closed_stream(StreamClose {
            stream_id,
            target: CloseTarget::Both,
            code: StreamCloseCode(0),
        });

        assert!(!state.streams.contains_key(&stream_id));
    }

    #[test]
    fn poll_stream_reaps_after_local_finish_when_inbound_is_closed() {
        let (mut state, mut fsm) = new_driver_state();
        let stream_id = StreamId(3);
        let (request_reader, request_writer) = piper::pipe(1);

        drop(request_writer);
        state.streams.insert(
            stream_id,
            DriverStreamIo::Initiator {
                request: OutboundIo::new(request_reader),
                response: InboundIo::Closed,
            },
        );

        state.poll_stream(&mut fsm, stream_id);

        assert!(!state.streams.contains_key(&stream_id));
    }

    #[test]
    fn local_close_command_reaps_when_other_half_is_already_closed() {
        let (mut state, mut fsm) = new_driver_state();
        let stream_id = StreamId(4);
        let (request_reader, _request_writer) = piper::pipe(1);
        let mut in_flight = Vec::new();

        state.streams.insert(
            stream_id,
            DriverStreamIo::Initiator {
                request: OutboundIo::new(request_reader),
                response: InboundIo::Closed,
            },
        );

        state.drive_command(
            &mut fsm,
            RuntimeCommand::CloseStream {
                stream_id,
                target: CloseTarget::Origin,
                code: StreamCloseCode(0),
            },
            &NoopPlatform,
            &mut in_flight,
        );

        assert!(!state.streams.contains_key(&stream_id));
    }
}
