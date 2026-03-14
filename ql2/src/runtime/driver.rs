use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    task::Poll,
    time::Instant,
};

use futures_lite::future::poll_fn;

use crate::{
    engine::{self, Engine, EngineInput, EngineOutput, OpenId},
    platform::{PlatformFuture, QlPlatform},
    runtime::{
        command::RuntimeCommand,
        handle::{InboundByteStream, InboundStream, StreamResponder},
        AcceptedStreamDelivery, HandlerEvent, InboundEvent, Runtime,
    },
    wire::stream::{BodyChunk, Direction, ResetCode},
    QlError, StreamId,
};

struct InFlightWrite<'a> {
    token: engine::Token,
    tracked: Option<engine::TrackedWrite>,
    future: PlatformFuture<'a, Result<(), QlError>>,
}

enum DriverEvent {
    Command(RuntimeCommand),
    WriteCompleted {
        token: engine::Token,
        tracked: Option<engine::TrackedWrite>,
        result: Result<(), QlError>,
    },
    TimerExpired,
    Closed,
}

struct PendingOpen {
    request_rx: async_channel::Receiver<Vec<u8>>,
    start_tx: oneshot::Sender<Result<StreamId, QlError>>,
    accepted_tx: oneshot::Sender<Result<AcceptedStreamDelivery, QlError>>,
}

struct PendingAcceptDelivery {
    tx: oneshot::Sender<Result<AcceptedStreamDelivery, QlError>>,
    response_rx: async_channel::Receiver<InboundEvent>,
}

enum OutboundIo {
    Open {
        dir: Direction,
        rx: async_channel::Receiver<Vec<u8>>,
        finish_queued: bool,
    },
    Closed,
}

impl OutboundIo {
    fn new(dir: Direction, rx: async_channel::Receiver<Vec<u8>>) -> Self {
        Self::Open {
            dir,
            rx,
            finish_queued: false,
        }
    }

    fn close(&mut self) {
        *self = Self::Closed;
    }

    fn poll_pending(&mut self, stream_id: StreamId, pending: &mut VecDeque<EngineInput>) {
        let Self::Open {
            dir,
            rx,
            finish_queued,
        } = self
        else {
            return;
        };

        match rx.try_recv() {
            Ok(bytes) => {
                if bytes.is_empty() {
                    return;
                }
                pending.push_back(EngineInput::OutboundData {
                    stream_id,
                    dir: *dir,
                    bytes,
                });
                if rx.is_closed() && rx.is_empty() && !*finish_queued {
                    *finish_queued = true;
                    pending.push_back(EngineInput::OutboundFinished { stream_id, dir: *dir });
                }
            }
            Err(async_channel::TryRecvError::Empty) => {
                if rx.is_closed() && !*finish_queued {
                    *finish_queued = true;
                    pending.push_back(EngineInput::OutboundFinished { stream_id, dir: *dir });
                }
            }
            Err(async_channel::TryRecvError::Closed) => {
                if !*finish_queued {
                    *finish_queued = true;
                    pending.push_back(EngineInput::OutboundFinished { stream_id, dir: *dir });
                }
            }
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

    fn write_or_cancel(
        &mut self,
        stream_id: StreamId,
        dir: Direction,
        bytes: Vec<u8>,
        pending: &mut VecDeque<EngineInput>,
    ) {
        let Self::Open(tx) = self else {
            pending.push_back(EngineInput::ResetInbound {
                stream_id,
                dir,
                code: ResetCode::Cancelled,
            });
            return;
        };
        if tx.try_send(InboundEvent::Data(bytes)).is_err() {
            tx.close();
            *self = Self::Closed;
            pending.push_back(EngineInput::ResetInbound {
                stream_id,
                dir,
                code: ResetCode::Cancelled,
            });
        }
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
        dir: Direction,
        prefix: &BodyChunk,
        pending: &mut VecDeque<EngineInput>,
    ) {
        if !prefix.bytes.is_empty() {
            self.write_or_cancel(stream_id, dir, prefix.bytes.clone(), pending);
        }
        if prefix.fin {
            self.finish();
        }
    }
}

enum PendingAcceptState {
    Waiting(PendingAcceptDelivery),
    Dropped,
    Resolved,
}

enum ResponderResponseIo {
    Pending,
    Streaming(OutboundIo),
    Rejected,
}

enum DriverStreamIo {
    Initiator {
        request: OutboundIo,
        response: InboundIo,
        pending_accept: PendingAcceptState,
    },
    Responder {
        request: InboundIo,
        response: ResponderResponseIo,
    },
}

impl DriverStreamIo {
    fn outbound_mut(&mut self, dir: Direction) -> Option<&mut OutboundIo> {
        match self {
            Self::Initiator { request, .. } if dir == Direction::Request => Some(request),
            Self::Responder {
                response: ResponderResponseIo::Streaming(outbound),
                ..
            } if dir == Direction::Response => Some(outbound),
            _ => None,
        }
    }

    fn inbound_mut(&mut self, dir: Direction) -> Option<&mut InboundIo> {
        match self {
            Self::Initiator { response, .. } if dir == Direction::Response => Some(response),
            Self::Responder { request, .. } if dir == Direction::Request => Some(request),
            _ => None,
        }
    }

    fn close_all(&mut self) {
        match self {
            Self::Initiator {
                request,
                response,
                pending_accept,
            } => {
                request.close();
                response.close();
                *pending_accept = PendingAcceptState::Resolved;
            }
            Self::Responder { request, response } => {
                request.close();
                if let ResponderResponseIo::Streaming(outbound) = response {
                    outbound.close();
                }
                *response = ResponderResponseIo::Rejected;
            }
        }
    }
}

struct DriverState {
    engine: Engine,
    pending_inputs: VecDeque<EngineInput>,
    next_timer: Option<Instant>,
    next_open_id: u64,
    pending_opens: HashMap<OpenId, PendingOpen>,
    streams: HashMap<StreamId, DriverStreamIo>,
}

impl DriverState {
    fn new(
        config: engine::EngineConfig,
        local_xid: bc_components::XID,
        peer: Option<crate::Peer>,
    ) -> Self {
        let engine = Engine::new(config, local_xid, peer);
        Self {
            engine,
            pending_inputs: VecDeque::new(),
            next_timer: None,
            next_open_id: 1,
            pending_opens: HashMap::new(),
            streams: HashMap::new(),
        }
    }

    fn push_input(&mut self, input: EngineInput) {
        self.pending_inputs.push_back(input);
    }

    fn translate_command(&mut self, command: RuntimeCommand) {
        match command {
            RuntimeCommand::BindPeer { peer } => self.push_input(EngineInput::BindPeer(peer)),
            RuntimeCommand::Pair => self.push_input(EngineInput::Pair),
            RuntimeCommand::Connect => self.push_input(EngineInput::Connect),
            RuntimeCommand::Unpair => self.push_input(EngineInput::Unpair),
            RuntimeCommand::Incoming(bytes) => self.push_input(EngineInput::Incoming(bytes)),
            RuntimeCommand::OpenStream {
                request_head,
                request_rx,
                accepted,
                start,
                config,
            } => {
                let open_id = OpenId(self.next_open_id);
                self.next_open_id = self.next_open_id.wrapping_add(1);
                self.pending_opens.insert(
                    open_id,
                    PendingOpen {
                        request_rx,
                        start_tx: start,
                        accepted_tx: accepted,
                    },
                );
                self.push_input(EngineInput::OpenStream {
                    open_id,
                    request_head,
                    request_prefix: None,
                    config,
                });
            }
            RuntimeCommand::AcceptStream {
                stream_id,
                response_head,
                response_rx,
            } => {
                if let Some(DriverStreamIo::Responder { response, .. }) =
                    self.streams.get_mut(&stream_id)
                {
                    *response = ResponderResponseIo::Streaming(OutboundIo::new(
                        Direction::Response,
                        response_rx,
                    ));
                }
                self.push_input(EngineInput::AcceptStream {
                    stream_id,
                    response_head,
                    response_prefix: None,
                });
            }
            RuntimeCommand::RejectStream { stream_id, code } => {
                if let Some(DriverStreamIo::Responder { response, .. }) =
                    self.streams.get_mut(&stream_id)
                {
                    *response = ResponderResponseIo::Rejected;
                }
                self.push_input(EngineInput::RejectStream { stream_id, code });
            }
            RuntimeCommand::PollStream { stream_id } => self.poll_stream(stream_id),
            RuntimeCommand::ResetOutbound {
                stream_id,
                dir,
                code,
            } => self.push_input(EngineInput::ResetOutbound {
                stream_id,
                dir,
                code,
            }),
            RuntimeCommand::ResetInbound {
                stream_id,
                dir,
                code,
            } => self.push_input(EngineInput::ResetInbound {
                stream_id,
                dir,
                code,
            }),
            RuntimeCommand::ResponderDropped { stream_id } => {
                self.push_input(EngineInput::ResponderDropped { stream_id });
            }
            RuntimeCommand::PendingAcceptDropped { stream_id } => {
                if let Some(DriverStreamIo::Initiator { pending_accept, .. }) =
                    self.streams.get_mut(&stream_id)
                {
                    if matches!(pending_accept, PendingAcceptState::Waiting(_)) {
                        *pending_accept = PendingAcceptState::Dropped;
                    }
                }
                self.push_input(EngineInput::PendingAcceptDropped { stream_id });
                self.push_input(EngineInput::ResetInbound {
                    stream_id,
                    dir: Direction::Response,
                    code: ResetCode::Cancelled,
                });
            }
        }
    }

    fn poll_stream(&mut self, stream_id: StreamId) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            match stream {
                DriverStreamIo::Initiator { request, .. } => {
                    request.poll_pending(stream_id, &mut self.pending_inputs)
                }
                DriverStreamIo::Responder { response, .. } => {
                    if let ResponderResponseIo::Streaming(outbound) = response {
                        outbound.poll_pending(stream_id, &mut self.pending_inputs);
                    }
                }
            }
        }
    }
}

impl<P: QlPlatform> Runtime<P> {
    pub async fn run(self) {
        let runtime_tx = self.tx.upgrade().expect("runtime tx");
        let local_xid = self.platform.xid();
        let mut state = DriverState::new(
            self.config.engine,
            local_xid,
            self.platform.load_peer().await,
        );
        let mut in_flight: Option<InFlightWrite<'_>> = None;

        loop {
            if let Some(input) = state.pending_inputs.pop_front() {
                let now = Instant::now();
                let pending_inputs = &mut state.pending_inputs;
                let next_timer = &mut state.next_timer;
                let pending_opens = &mut state.pending_opens;
                let streams = &mut state.streams;
                state
                    .engine
                    .run_tick(now, input, &self.platform, &mut |output| {
                        self.apply_output(
                            pending_inputs,
                            next_timer,
                            pending_opens,
                            streams,
                            &runtime_tx,
                            &mut in_flight,
                            output,
                        );
                    });
                continue;
            }

            if self.rx.is_closed() {
                break;
            }

            match self
                .next_driver_event(state.next_timer, in_flight.as_mut())
                .await
            {
                DriverEvent::Command(command) => state.translate_command(command),
                DriverEvent::WriteCompleted {
                    token,
                    tracked,
                    result,
                } => {
                    in_flight = None;
                    state.push_input(EngineInput::WriteCompleted {
                        token,
                        tracked,
                        result,
                    });
                }
                DriverEvent::TimerExpired => state.push_input(EngineInput::TimerExpired),
                DriverEvent::Closed => break,
            }
        }
    }

    async fn next_driver_event<'a>(
        &'a self,
        next_timer: Option<Instant>,
        mut in_flight: Option<&mut InFlightWrite<'a>>,
    ) -> DriverEvent {
        let recv_future = self.rx.recv();
        futures_lite::pin!(recv_future);

        let mut sleep_future = next_timer.map(|deadline| {
            let timeout = deadline.saturating_duration_since(Instant::now());
            self.platform.sleep(timeout)
        });

        poll_fn(|cx| {
            if let Some(in_flight) = in_flight.as_mut() {
                if let Poll::Ready(result) = in_flight.future.as_mut().poll(cx) {
                    return Poll::Ready(DriverEvent::WriteCompleted {
                        token: in_flight.token,
                        tracked: in_flight.tracked,
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

    fn apply_output<'a>(
        &'a self,
        pending_inputs: &mut VecDeque<EngineInput>,
        next_timer: &mut Option<Instant>,
        pending_opens: &mut HashMap<OpenId, PendingOpen>,
        streams: &mut HashMap<StreamId, DriverStreamIo>,
        runtime_tx: &async_channel::Sender<RuntimeCommand>,
        in_flight: &mut Option<InFlightWrite<'a>>,
        output: EngineOutput,
    ) {
        match output {
            EngineOutput::SetTimer(deadline) => *next_timer = deadline,
            EngineOutput::WriteMessage {
                token,
                tracked,
                bytes,
            } => {
                *in_flight = Some(InFlightWrite {
                    token,
                    tracked,
                    future: self.platform.write_message(bytes),
                });
            }
            EngineOutput::PeerStatusChanged { peer, session } => {
                self.platform.handle_peer_status(peer, &session);
            }
            EngineOutput::PersistPeer(peer) => self.platform.persist_peer(peer),
            EngineOutput::ClearPeer => self.platform.clear_peer(),
            EngineOutput::OpenStarted { open_id, stream_id } => {
                let Some(pending) = pending_opens.remove(&open_id) else {
                    return;
                };
                let _ = pending.start_tx.send(Ok(stream_id));
                let (response_tx, response_rx) = async_channel::unbounded();
                streams.insert(
                    stream_id,
                    DriverStreamIo::Initiator {
                        request: OutboundIo::new(Direction::Request, pending.request_rx),
                        response: InboundIo::new(response_tx),
                        pending_accept: PendingAcceptState::Waiting(PendingAcceptDelivery {
                            tx: pending.accepted_tx,
                            response_rx,
                        }),
                    },
                );
            }
            EngineOutput::OpenAccepted {
                stream_id,
                response_head,
                response_prefix,
                ..
            } => {
                let Some(DriverStreamIo::Initiator {
                    response,
                    pending_accept,
                    ..
                }) = streams.get_mut(&stream_id)
                else {
                    return;
                };
                if let Some(prefix) = response_prefix.as_ref() {
                    response.apply_prefix(stream_id, Direction::Response, prefix, pending_inputs);
                }
                match std::mem::replace(pending_accept, PendingAcceptState::Resolved) {
                    PendingAcceptState::Waiting(delivery) => {
                        let _ = delivery.tx.send(Ok(AcceptedStreamDelivery {
                            stream_id,
                            response_head,
                            response: delivery.response_rx,
                            tx: runtime_tx.clone(),
                        }));
                    }
                    PendingAcceptState::Dropped => {
                        *pending_accept = PendingAcceptState::Dropped;
                    }
                    PendingAcceptState::Resolved => {}
                }
            }
            EngineOutput::OpenFailed {
                open_id,
                stream_id,
                error,
            } => {
                if let Some(pending) = pending_opens.remove(&open_id) {
                    let _ = pending.start_tx.send(Err(error));
                    return;
                }
                let Some(DriverStreamIo::Initiator { pending_accept, .. }) =
                    streams.get_mut(&stream_id)
                else {
                    return;
                };
                match std::mem::replace(pending_accept, PendingAcceptState::Resolved) {
                    PendingAcceptState::Waiting(delivery) => {
                        let _ = delivery.tx.send(Err(error));
                    }
                    PendingAcceptState::Dropped => {
                        *pending_accept = PendingAcceptState::Dropped;
                    }
                    PendingAcceptState::Resolved => {}
                }
            }
            EngineOutput::InboundStreamOpened {
                stream_id,
                request_head,
                request_prefix,
            } => {
                let (request_tx, request_rx) = async_channel::unbounded();
                let mut request = InboundIo::new(request_tx);
                if let Some(prefix) = request_prefix.as_ref() {
                    request.apply_prefix(stream_id, Direction::Request, prefix, pending_inputs);
                }
                streams.insert(
                    stream_id,
                    DriverStreamIo::Responder {
                        request,
                        response: ResponderResponseIo::Pending,
                    },
                );
                self.platform
                    .handle_inbound(HandlerEvent::Stream(InboundStream {
                        stream_id,
                        request_head,
                        request: InboundByteStream::new(
                            stream_id,
                            Direction::Request,
                            request_rx,
                            runtime_tx.clone(),
                        ),
                        respond_to: StreamResponder::new(stream_id, runtime_tx.clone()),
                    }));
            }
            EngineOutput::InboundData {
                stream_id,
                dir,
                bytes,
            } => {
                if let Some(stream) = streams.get_mut(&stream_id) {
                    if let Some(inbound) = stream.inbound_mut(dir) {
                        inbound.write_or_cancel(stream_id, dir, bytes, pending_inputs);
                    }
                }
            }
            EngineOutput::InboundFinished { stream_id, dir } => {
                if let Some(stream) = streams.get_mut(&stream_id) {
                    if let Some(inbound) = stream.inbound_mut(dir) {
                        inbound.finish();
                    }
                }
            }
            EngineOutput::InboundFailed {
                stream_id,
                dir,
                error,
            } => {
                if let Some(stream) = streams.get_mut(&stream_id) {
                    if let Some(inbound) = stream.inbound_mut(dir) {
                        inbound.fail(error);
                    }
                }
            }
            EngineOutput::OutboundClosed { stream_id, dir }
            | EngineOutput::OutboundFailed { stream_id, dir, .. } => {
                if let Some(stream) = streams.get_mut(&stream_id) {
                    if let Some(outbound) = stream.outbound_mut(dir) {
                        outbound.close();
                    }
                }
            }
            EngineOutput::StreamReaped { stream_id } => {
                if let Some(mut stream) = streams.remove(&stream_id) {
                    stream.close_all();
                }
            }
        }
    }
}

fn poll_stream(
    streams: &mut HashMap<StreamId, DriverStreamIo>,
    pending_inputs: &mut VecDeque<EngineInput>,
    stream_id: StreamId,
) {
    if let Some(stream) = streams.get_mut(&stream_id) {
        match stream {
            DriverStreamIo::Initiator { request, .. } => {
                request.poll_pending(stream_id, pending_inputs)
            }
            DriverStreamIo::Responder { response, .. } => {
                if let ResponderResponseIo::Streaming(outbound) = response {
                    outbound.poll_pending(stream_id, pending_inputs);
                }
            }
        }
    }
}
