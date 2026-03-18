use std::{
    collections::HashMap,
    future::Future,
    task::Poll,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use futures_lite::future::poll_fn;
use ql_fsm::{FsmTime, QlFsm, QlFsmEvent, QlSessionEvent, SessionWriteId};

use crate::{
    command::RuntimeCommand,
    handle::{ByteReader, ByteWriter, InboundStream},
    platform::{PlatformFuture, QlPlatform},
    CloseCode, CloseTarget, InboundEvent, OpenedStreamDelivery, QlError, Runtime, StreamId,
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

    fn take_pending(&mut self) -> (Option<Vec<u8>>, bool) {
        let Self::Open {
            reader,
            finish_queued,
        } = self
        else {
            return (None, false);
        };

        let mut drained = None;
        let available = reader.len();
        if available > 0 {
            let mut bytes = vec![0; available];
            let read = reader.try_drain(&mut bytes);
            if read > 0 {
                bytes.truncate(read);
                drained = Some(bytes);
            }
        }

        let mut finished = false;
        if reader.is_closed() && !*finish_queued {
            *finish_queued = true;
            finished = true;
        }

        (drained, finished)
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
            Self::Initiator { .. } => CloseTarget::Response,
            Self::Responder { .. } => CloseTarget::Request,
        }
    }

    fn outbound_target(&self) -> CloseTarget {
        match self {
            Self::Initiator { .. } => CloseTarget::Request,
            Self::Responder { .. } => CloseTarget::Response,
        }
    }

    fn fail_all(&mut self, error: QlError) {
        match self {
            Self::Initiator { request, response } => {
                request.close();
                response.fail(error);
            }
            Self::Responder { request, response } => {
                request.fail(error);
                response.close();
            }
        }
    }
}

struct DriverState {
    fsm: QlFsm,
    streams: HashMap<StreamId, DriverStreamIo>,
    runtime_tx: async_channel::Sender<RuntimeCommand>,
    stream_send_buffer_bytes: usize,
    max_concurrent_message_writes: usize,
}

impl DriverState {
    fn drive_command<'a, P: QlPlatform>(
        &mut self,
        command: RuntimeCommand,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<'a>>,
    ) {
        match command {
            RuntimeCommand::BindPeer { peer } => {
                self.fsm.bind_peer(peer);
                self.finish_step(platform, in_flight);
            }
            RuntimeCommand::Pair => {
                let _ = self.fsm.pair(now(), platform);
                self.finish_step(platform, in_flight);
            }
            RuntimeCommand::Connect => {
                let _ = self.fsm.connect(now(), platform);
                self.finish_step(platform, in_flight);
            }
            RuntimeCommand::Unpair => {
                let _ = self.fsm.queue_unpair();
                self.finish_step(platform, in_flight);
            }
            RuntimeCommand::Incoming(bytes) => {
                let _ = self.fsm.receive(now(), bytes, platform);
                self.finish_step(platform, in_flight);
            }
            RuntimeCommand::OpenStream {
                request_reader,
                start,
            } => match self.fsm.open_stream().map_err(QlError::from) {
                Ok(stream_id) => {
                    let (response_tx, response_rx) = async_channel::unbounded();
                    self.streams.insert(
                        stream_id,
                        DriverStreamIo::Initiator {
                            request: OutboundIo::new(request_reader),
                            response: InboundIo::new(response_tx),
                        },
                    );
                    let _ = start.send(Ok(OpenedStreamDelivery {
                        stream_id,
                        response: response_rx,
                    }));
                    self.poll_stream(stream_id);
                    self.finish_step(platform, in_flight);
                }
                Err(error) => {
                    let _ = start.send(Err(error));
                }
            },
            RuntimeCommand::PollStream { stream_id } => {
                self.poll_stream(stream_id);
                self.finish_step(platform, in_flight);
            }
            RuntimeCommand::CloseStream {
                stream_id,
                target,
                code,
                payload,
            } => {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    if target == CloseTarget::Both || target == stream.inbound_target() {
                        stream.inbound_mut().close();
                    }
                    if target == CloseTarget::Both || target == stream.outbound_target() {
                        stream.outbound_mut().close();
                    }
                }
                let _ = self.fsm.close_stream(stream_id, target, code, payload);
                self.try_reap_stream(stream_id);
                self.finish_step(platform, in_flight);
            }
        }
    }

    fn drive_write_completed<'a, P: QlPlatform>(
        &mut self,
        session_write_id: Option<SessionWriteId>,
        result: Result<(), QlError>,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<'a>>,
    ) {
        if let Some(write_id) = session_write_id {
            match result {
                Ok(()) => self.fsm.confirm_session_write(now(), write_id),
                Err(_) => self.fsm.reject_session_write(write_id),
            }
        }
        self.finish_step(platform, in_flight);
    }

    fn finish_step<'a, P: QlPlatform>(
        &mut self,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<'a>>,
    ) {
        loop {
            let mut progressed = false;

            progressed |= self.drain_fsm(platform);
            progressed |= self.fill_write_slots(platform, in_flight);

            if !progressed {
                break;
            }
        }
    }

    fn drain_fsm<P: QlPlatform>(&mut self, platform: &P) -> bool {
        let mut progressed = false;

        while let Some(event) = self.fsm.take_next_event() {
            progressed = true;
            match event {
                QlFsmEvent::NewPeer(peer) => platform.persist_peer(peer),
                QlFsmEvent::ClearPeer => platform.clear_peer(),
                QlFsmEvent::PeerStatusChanged { peer, status } => {
                    platform.handle_peer_status(peer, status)
                }
            }
        }

        while let Some(event) = self.fsm.take_next_session_event() {
            progressed = true;
            match event {
                QlSessionEvent::Opened(stream_id) => self.handle_opened_stream(platform, stream_id),
                QlSessionEvent::Readable(stream_id) => self.handle_inbound_readable(stream_id),
                QlSessionEvent::Finished(stream_id) => self.handle_inbound_finished(stream_id),
                QlSessionEvent::Closed(frame) => self.handle_closed_stream(frame),
                QlSessionEvent::WritableClosed(stream_id) => self.handle_writable_closed(stream_id),
                QlSessionEvent::Unpaired => self.fail_all_streams(QlError::Cancelled),
                QlSessionEvent::SessionClosed(_) => self.fail_all_streams(QlError::SessionClosed),
            }
        }

        progressed
    }

    fn handle_opened_stream<P: QlPlatform>(&mut self, platform: &P, stream_id: StreamId) {
        let (request_tx, request_rx) = async_channel::unbounded();
        let (response_reader, response_writer) = piper::pipe(self.stream_send_buffer_bytes);

        self.streams.insert(
            stream_id,
            DriverStreamIo::Responder {
                request: InboundIo::new(request_tx),
                response: OutboundIo::new(response_reader),
            },
        );

        platform.handle_inbound(InboundStream {
            stream_id,
            request: ByteReader::new(
                stream_id,
                CloseTarget::Request,
                request_rx,
                self.runtime_tx.clone(),
            ),
            response: ByteWriter::new(
                stream_id,
                CloseTarget::Response,
                response_writer,
                self.runtime_tx.clone(),
            ),
        });
    }

    fn handle_inbound_readable(&mut self, stream_id: StreamId) {
        loop {
            let max_len = self.fsm.config.session_stream_chunk_size.max(1);
            let available = match self.fsm.stream_available_bytes(stream_id) {
                Ok(available) => available,
                Err(_) => return,
            };
            if available == 0 {
                break;
            }

            let mut bytes = vec![0; available.min(max_len)];
            let read = match self.fsm.read_stream(stream_id, &mut bytes) {
                Ok(read) => read,
                Err(_) => return,
            };
            bytes.truncate(read);

            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return;
            };
            let target = stream.inbound_target();
            let should_close = stream.inbound_mut().write_or_close(bytes);
            if should_close {
                let _ = self
                    .fsm
                    .close_stream(stream_id, target, CloseCode::CANCELLED, Vec::new());
                self.try_reap_stream(stream_id);
                break;
            }
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
            payload: frame.payload.clone(),
        };

        if frame.target == CloseTarget::Both || frame.target == stream.inbound_target() {
            stream.inbound_mut().fail(error);
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
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<'a>>,
    ) -> bool {
        let mut progressed = false;

        while in_flight.len() < self.max_concurrent_message_writes {
            let Some(write) = self.fsm.take_next_write(now(), platform) else {
                break;
            };
            progressed = true;
            in_flight.push(InFlightWrite {
                session_write_id: write.session_write_id,
                future: platform.write_message(write.record.encode()),
            });
        }

        progressed
    }

    fn poll_stream(&mut self, stream_id: StreamId) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let (bytes, finished) = stream.outbound_mut().take_pending();
        if let Some(bytes) = bytes {
            let _ = self.fsm.write_stream(stream_id, bytes);
        }
        if finished {
            let _ = self.fsm.finish_stream(stream_id);
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.outbound_mut().close();
            }
            self.try_reap_stream(stream_id);
        }
    }

    fn try_reap_stream(&mut self, stream_id: StreamId) {
        let should_reap = self
            .streams
            .get(&stream_id)
            .is_some_and(|stream| match stream {
                DriverStreamIo::Initiator { request, response } => {
                    matches!(request, OutboundIo::Closed) && matches!(response, InboundIo::Closed)
                }
                DriverStreamIo::Responder { request, response } => {
                    matches!(request, InboundIo::Closed) && matches!(response, OutboundIo::Closed)
                }
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
        if let Some(peer) = platform.load_peer().await {
            fsm.bind_peer(peer);
        }

        let mut state = DriverState {
            fsm,
            streams: HashMap::new(),
            runtime_tx,
            stream_send_buffer_bytes: config.stream_send_buffer_bytes,
            max_concurrent_message_writes: config.max_concurrent_message_writes,
        };
        let mut in_flight = Vec::new();

        loop {
            state.finish_step(&platform, &mut in_flight);

            if rx.is_closed() && in_flight.is_empty() {
                break;
            }

            match next_driver_event(&rx, &platform, state.fsm.next_deadline(), &mut in_flight).await
            {
                DriverEvent::Command(command) => {
                    state.drive_command(command, &platform, &mut in_flight)
                }
                DriverEvent::WriteCompleted { index, result } => {
                    let write = in_flight.swap_remove(index);
                    state.drive_write_completed(
                        write.session_write_id,
                        result,
                        &platform,
                        &mut in_flight,
                    );
                }
                DriverEvent::TimerExpired => {
                    state.fsm.on_timer(now());
                    state.finish_step(&platform, &mut in_flight);
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

#[cfg(test)]
mod tests {
    use ql_fsm::Peer;
    use ql_wire::{CloseCode, StreamClose, XID};

    use super::*;
    use crate::tests::new_identity;

    struct NoopPlatform;

    impl ql_wire::QlCrypto for NoopPlatform {
        fn fill_random_bytes(&self, data: &mut [u8]) {
            data.fill(0);
        }

        fn hash(&self, _parts: &[&[u8]]) -> [u8; 32] {
            [0; 32]
        }

        fn encrypt_with_aead(
            &self,
            _key: &ql_wire::SessionKey,
            _nonce: &ql_wire::Nonce,
            _aad: &[u8],
            _buffer: &mut [u8],
        ) -> Option<[u8; ql_wire::EncryptedMessage::AUTH_SIZE]> {
            None
        }

        fn decrypt_with_aead(
            &self,
            _key: &ql_wire::SessionKey,
            _nonce: &ql_wire::Nonce,
            _aad: &[u8],
            _buffer: &mut [u8],
            _auth_tag: &[u8; ql_wire::EncryptedMessage::AUTH_SIZE],
        ) -> bool {
            false
        }
    }

    impl QlPlatform for NoopPlatform {
        fn write_message(&self, _message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>> {
            Box::pin(async { Ok(()) })
        }

        fn sleep(&self, _duration: Duration) -> PlatformFuture<'_, ()> {
            Box::pin(async {})
        }

        fn load_peer(&self) -> PlatformFuture<'_, Option<Peer>> {
            Box::pin(async { None })
        }

        fn persist_peer(&self, _peer: Peer) {}

        fn clear_peer(&self) {}

        fn handle_peer_status(&self, _peer: XID, _status: ql_fsm::PeerStatus) {}

        fn handle_inbound(&self, _event: InboundStream) {}
    }

    fn new_driver_state() -> DriverState {
        let (runtime_tx, _runtime_rx) = async_channel::unbounded();
        DriverState {
            fsm: QlFsm::new(ql_fsm::QlFsmConfig::default(), new_identity(7), now()),
            streams: HashMap::new(),
            runtime_tx,
            stream_send_buffer_bytes: 16,
            max_concurrent_message_writes: 1,
        }
    }

    #[test]
    fn handle_inbound_finished_reaps_closed_initiator_stream() {
        let mut state = new_driver_state();
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
        let mut state = new_driver_state();
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
            code: CloseCode::CANCELLED,
            payload: Vec::new(),
        });

        assert!(!state.streams.contains_key(&stream_id));
    }

    #[test]
    fn poll_stream_reaps_after_local_finish_when_inbound_is_closed() {
        let mut state = new_driver_state();
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

        state.poll_stream(stream_id);

        assert!(!state.streams.contains_key(&stream_id));
    }

    #[test]
    fn local_close_command_reaps_when_other_half_is_already_closed() {
        let mut state = new_driver_state();
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
            RuntimeCommand::CloseStream {
                stream_id,
                target: CloseTarget::Request,
                code: CloseCode::CANCELLED,
                payload: Vec::new(),
            },
            &NoopPlatform,
            &mut in_flight,
        );

        assert!(!state.streams.contains_key(&stream_id));
    }
}
