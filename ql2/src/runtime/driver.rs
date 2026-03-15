use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    task::Poll,
    time::Instant,
};

use futures_lite::future::poll_fn;

use crate::{
    engine::{Engine, EngineInput, EngineOutput, WriteId},
    runtime::{
        command::RuntimeCommand,
        handle::{InboundByteStream, InboundStream, OutboundByteStream},
        platform::{PlatformFuture, QlPlatform},
        HandlerEvent, InboundEvent, OpenedStreamDelivery, Runtime,
    },
    wire::stream::{BodyChunk, CloseCode, CloseTarget},
    QlError, StreamId,
};

struct InFlightWrite<'a> {
    id: WriteId,
    future: PlatformFuture<'a, Result<(), QlError>>,
}

enum DriverEvent {
    Command(RuntimeCommand),
    WriteCompleted {
        write_id: WriteId,
        result: Result<(), QlError>,
    },
    TimerExpired,
    Closed,
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

    fn poll_pending(&mut self, stream_id: StreamId, pending_inputs: &mut VecDeque<EngineInput>) {
        let Self::Open {
            reader,
            finish_queued,
        } = self
        else {
            return;
        };

        let available = reader.len();
        if available > 0 {
            let mut bytes = vec![0; available];
            let read = reader.try_drain(&mut bytes);
            if read > 0 {
                bytes.truncate(read);
                pending_inputs.push_back(EngineInput::OutboundData { stream_id, bytes });
            }
        }

        if reader.is_closed() && !*finish_queued {
            *finish_queued = true;
            pending_inputs.push_back(EngineInput::OutboundFinished { stream_id });
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

    fn write_or_close(
        &mut self,
        stream_id: StreamId,
        target: CloseTarget,
        bytes: Vec<u8>,
    ) -> Option<EngineInput> {
        let Self::Open(tx) = self else {
            return Some(EngineInput::CloseStream {
                stream_id,
                target,
                code: CloseCode::CANCELLED,
                payload: Vec::new(),
            });
        };
        if tx.try_send(InboundEvent::Data(bytes)).is_err() {
            tx.close();
            *self = Self::Closed;
            return Some(EngineInput::CloseStream {
                stream_id,
                target,
                code: CloseCode::CANCELLED,
                payload: Vec::new(),
            });
        }
        None
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

    fn close(&mut self) {
        if let Self::Open(tx) = self {
            let _ = tx.try_send(InboundEvent::Failed(QlError::Cancelled));
            tx.close();
        }
        *self = Self::Closed;
    }

    fn apply_prefix(
        &mut self,
        stream_id: StreamId,
        target: CloseTarget,
        prefix: &BodyChunk,
    ) -> Option<EngineInput> {
        let mut input = None;
        if !prefix.bytes.is_empty() {
            input = self.write_or_close(stream_id, target, prefix.bytes.clone());
        }
        if prefix.fin {
            self.finish();
        }
        input
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
    fn poll_pending(&mut self, stream_id: StreamId, pending_inputs: &mut VecDeque<EngineInput>) {
        match self {
            Self::Initiator { request, .. } => request.poll_pending(stream_id, pending_inputs),
            Self::Responder { response, .. } => response.poll_pending(stream_id, pending_inputs),
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
            Self::Initiator { .. } => CloseTarget::Response,
            Self::Responder { .. } => CloseTarget::Request,
        }
    }

    fn close_all(&mut self) {
        match self {
            Self::Initiator { request, response } => {
                request.close();
                response.close();
            }
            Self::Responder { request, response } => {
                request.close();
                response.close();
            }
        }
    }
}

struct DriverState {
    engine: Engine,
    pending_inputs: VecDeque<EngineInput>,
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
                self.drive_input(EngineInput::BindPeer(peer), platform, in_flight);
            }
            RuntimeCommand::Pair => {
                self.drive_input(EngineInput::Pair, platform, in_flight);
            }
            RuntimeCommand::Connect => {
                self.drive_input(EngineInput::Connect, platform, in_flight);
            }
            RuntimeCommand::Unpair => {
                self.drive_input(EngineInput::Unpair, platform, in_flight);
            }
            RuntimeCommand::Incoming(bytes) => {
                self.drive_input(EngineInput::Incoming(bytes), platform, in_flight);
            }
            RuntimeCommand::OpenStream {
                request_head,
                request_reader,
                start,
                config,
            } => {
                match self
                    .engine
                    .open_stream(Instant::now(), request_head, None, config)
                {
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
                        self.drive_pending(platform, in_flight);
                    }
                    Err(error) => {
                        let _ = start.send(Err(error));
                    }
                }
            }
            RuntimeCommand::PollStream { stream_id } => {
                self.poll_stream(stream_id);
                self.drive_pending(platform, in_flight);
            }
            RuntimeCommand::CloseStream {
                stream_id,
                target,
                code,
                payload,
            } => {
                self.drive_input(
                    EngineInput::CloseStream {
                        stream_id,
                        target,
                        code,
                        payload,
                    },
                    platform,
                    in_flight,
                );
            }
        }
    }

    fn drive_input<'a, P: QlPlatform>(
        &mut self,
        input: EngineInput,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<'a>>,
    ) {
        self.pending_inputs.push_back(input);
        self.drive_pending(platform, in_flight);
    }

    fn drive_write_completed<'a, P: QlPlatform>(
        &mut self,
        write_id: WriteId,
        result: Result<(), QlError>,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<'a>>,
    ) {
        {
            let runtime_tx = self.runtime_tx.clone();
            let stream_send_buffer_bytes = self.stream_send_buffer_bytes;
            let pending_inputs = &mut self.pending_inputs;
            let streams = &mut self.streams;
            self.engine.complete_write(write_id, result, &mut |output| {
                handle_output(
                    output,
                    platform,
                    &runtime_tx,
                    stream_send_buffer_bytes,
                    pending_inputs,
                    streams,
                )
            });
        }
        self.fill_write_slots(platform, in_flight);
        self.drive_pending(platform, in_flight);
    }

    fn drive_pending<'a, P: QlPlatform>(
        &mut self,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<'a>>,
    ) {
        while let Some(input) = self.pending_inputs.pop_front() {
            {
                let runtime_tx = &self.runtime_tx;
                let stream_send_buffer_bytes = self.stream_send_buffer_bytes;
                let pending_inputs = &mut self.pending_inputs;
                let streams = &mut self.streams;
                self.engine
                    .run_tick(Instant::now(), input, platform, &mut |output| {
                        handle_output(
                            output,
                            platform,
                            runtime_tx,
                            stream_send_buffer_bytes,
                            pending_inputs,
                            streams,
                        )
                    });
            }
            self.fill_write_slots(platform, in_flight);
        }

        self.fill_write_slots(platform, in_flight);
    }

    fn fill_write_slots<'a, P: QlPlatform>(
        &mut self,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<'a>>,
    ) {
        while in_flight.len() < self.max_concurrent_message_writes {
            let Some(write) = self.engine.take_next_write(platform) else {
                break;
            };
            in_flight.push(InFlightWrite {
                id: write.id,
                future: platform.write_message(write.bytes),
            });
        }
    }

    fn poll_stream(&mut self, stream_id: StreamId) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        stream.poll_pending(stream_id, &mut self.pending_inputs);
    }
}

fn handle_output<P: QlPlatform>(
    output: EngineOutput,
    platform: &P,
    runtime_tx: &async_channel::Sender<RuntimeCommand>,
    stream_send_buffer_bytes: usize,
    pending_inputs: &mut VecDeque<EngineInput>,
    streams: &mut HashMap<StreamId, DriverStreamIo>,
) {
    match output {
        EngineOutput::PeerStatusChanged { peer, session } => {
            platform.handle_peer_status(peer, &session);
        }
        EngineOutput::PersistPeer(peer) => platform.persist_peer(peer),
        EngineOutput::ClearPeer => platform.clear_peer(),
        EngineOutput::InboundStreamOpened {
            stream_id,
            request_head,
            request_prefix,
        } => {
            let (request_tx, request_rx) = async_channel::unbounded();
            let mut request = InboundIo::new(request_tx);
            if let Some(prefix) = request_prefix.as_ref() {
                if let Some(input) = request.apply_prefix(stream_id, CloseTarget::Request, prefix) {
                    pending_inputs.push_back(input);
                }
            }

            let (response_reader, response_writer) = piper::pipe(stream_send_buffer_bytes);
            streams.insert(
                stream_id,
                DriverStreamIo::Responder {
                    request,
                    response: OutboundIo::new(response_reader),
                },
            );

            platform.handle_inbound(HandlerEvent::Stream(InboundStream {
                stream_id,
                request_head,
                request: InboundByteStream::new(
                    stream_id,
                    CloseTarget::Request,
                    request_rx,
                    runtime_tx.clone(),
                ),
                response: OutboundByteStream::new(
                    stream_id,
                    CloseTarget::Response,
                    response_writer,
                    runtime_tx.clone(),
                ),
            }));
        }
        EngineOutput::InboundData { stream_id, bytes } => {
            let Some(stream) = streams.get_mut(&stream_id) else {
                return;
            };
            let target = stream.inbound_target();
            let inbound = stream.inbound_mut();
            if let Some(input) = inbound.write_or_close(stream_id, target, bytes) {
                pending_inputs.push_back(input);
            }
        }
        EngineOutput::InboundFinished { stream_id } => {
            let Some(stream) = streams.get_mut(&stream_id) else {
                return;
            };
            stream.inbound_mut().finish();
        }
        EngineOutput::InboundFailed { stream_id, error } => {
            let Some(stream) = streams.get_mut(&stream_id) else {
                return;
            };
            stream.inbound_mut().fail(error);
        }
        EngineOutput::OutboundClosed { stream_id }
        | EngineOutput::OutboundFailed { stream_id, .. } => {
            let Some(stream) = streams.get_mut(&stream_id) else {
                return;
            };
            stream.outbound_mut().close();
        }
        EngineOutput::StreamReaped { stream_id } => {
            if let Some(mut stream) = streams.remove(&stream_id) {
                stream.close_all();
            }
        }
    }
}

async fn next_driver_event<P: QlPlatform>(
    rx: &async_channel::Receiver<RuntimeCommand>,
    platform: &P,
    next_timer: Option<Instant>,
    in_flight: &mut Vec<InFlightWrite<'_>>,
) -> DriverEvent {
    let recv_future = rx.recv();
    futures_lite::pin!(recv_future);

    let mut sleep_future = next_timer.map(|deadline| {
        let timeout = deadline.saturating_duration_since(Instant::now());
        platform.sleep(timeout)
    });

    poll_fn(|cx| {
        for write in in_flight.iter_mut() {
            if let Poll::Ready(result) = write.future.as_mut().poll(cx) {
                return Poll::Ready(DriverEvent::WriteCompleted {
                    write_id: write.id,
                    result,
                });
            }
        }

        if let Some(future) = sleep_future.as_mut() {
            if let Poll::Ready(()) = future.as_mut().poll(cx) {
                return Poll::Ready(DriverEvent::TimerExpired);
            }
        }

        recv_future.as_mut().poll(cx).map(|res| match res {
            Ok(command) => DriverEvent::Command(command),
            Err(_) => DriverEvent::Closed,
        })
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
        let peer = platform.load_peer().await;
        let runtime_tx = tx.upgrade().expect("runtime tx");
        let mut state = DriverState {
            engine: Engine::new(config.engine, identity, peer),
            pending_inputs: VecDeque::new(),
            streams: HashMap::new(),
            runtime_tx,
            stream_send_buffer_bytes: config.stream_send_buffer_bytes,
            max_concurrent_message_writes: config.max_concurrent_message_writes,
        };
        let mut in_flight = Vec::new();

        loop {
            state.drive_pending(&platform, &mut in_flight);

            if rx.is_closed() && state.pending_inputs.is_empty() && in_flight.is_empty() {
                break;
            }

            match next_driver_event(&rx, &platform, state.engine.next_deadline(), &mut in_flight)
                .await
            {
                DriverEvent::Command(command) => {
                    state.drive_command(command, &platform, &mut in_flight);
                }
                DriverEvent::WriteCompleted { write_id, result } => {
                    if let Some(index) = in_flight.iter().position(|write| write.id == write_id) {
                        in_flight.swap_remove(index);
                    }
                    state.drive_write_completed(write_id, result, &platform, &mut in_flight);
                }
                DriverEvent::TimerExpired => {
                    state.drive_input(EngineInput::TimerExpired, &platform, &mut in_flight);
                }
                DriverEvent::Closed => break,
            }
        }
    }
}
