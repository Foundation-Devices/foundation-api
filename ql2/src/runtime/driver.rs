use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io::Read,
    task::Poll,
    time::Instant,
};

use futures_lite::future::poll_fn;

use crate::{
    pipe,
    platform::{PlatformFuture, QlPlatform},
    runtime::{
        engine::{self, Engine, EngineInput, EngineOutput, OpenId},
        handle::{InboundByteStream, InboundStream, StreamResponder},
        AcceptedStreamDelivery, HandlerEvent, Runtime,
    },
    QlError, StreamId,
};
use crate::wire::stream::{Direction, ResetCode};

pub(crate) enum RuntimeCommand {
    BindPeer { peer: crate::Peer },
    Pair,
    Connect,
    Unpair,
    OpenStream {
        request_head: Vec<u8>,
        request_pipe: pipe::PipeReader<QlError>,
        accepted: oneshot::Sender<Result<AcceptedStreamDelivery, QlError>>,
        start: oneshot::Sender<Result<StreamId, QlError>>,
        config: crate::runtime::StreamConfig,
    },
    AcceptStream {
        stream_id: StreamId,
        response_head: Vec<u8>,
        response_pipe: pipe::PipeReader<QlError>,
    },
    RejectStream {
        stream_id: StreamId,
        code: crate::wire::stream::RejectCode,
    },
    PollStream {
        stream_id: StreamId,
    },
    AdvanceInboundCredit {
        stream_id: StreamId,
        dir: Direction,
        amount: u64,
    },
    ResetOutbound {
        stream_id: StreamId,
        dir: Direction,
        code: ResetCode,
    },
    ResetInbound {
        stream_id: StreamId,
        dir: Direction,
        code: ResetCode,
    },
    ResponderDropped {
        stream_id: StreamId,
    },
    PendingAcceptDropped {
        stream_id: StreamId,
    },
    Incoming(Vec<u8>),
}

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
    request_pipe: pipe::PipeReader<QlError>,
    start_tx: oneshot::Sender<Result<StreamId, QlError>>,
    accepted_tx: oneshot::Sender<Result<AcceptedStreamDelivery, QlError>>,
}

struct PendingAcceptDelivery {
    tx: oneshot::Sender<Result<AcceptedStreamDelivery, QlError>>,
    response_reader: pipe::PipeReader<QlError>,
}

#[derive(Debug, Clone, Copy)]
struct PendingPull {
    offset: u64,
    max_len: usize,
}

enum OutboundIo {
    Open {
        dir: Direction,
        pipe: pipe::PipeReader<QlError>,
        pending_pull: Option<PendingPull>,
        finish_queued: bool,
    },
    Closed,
}

impl OutboundIo {
    fn new(dir: Direction, pipe: pipe::PipeReader<QlError>) -> Self {
        Self::Open {
            dir,
            pipe,
            pending_pull: None,
            finish_queued: false,
        }
    }

    fn set_pending_pull(&mut self, offset: u64, max_len: usize) {
        if let Self::Open { pending_pull, .. } = self {
            *pending_pull = Some(PendingPull { offset, max_len });
        }
    }

    fn release_to(&mut self, recv_offset: u64) {
        if let Self::Open { pipe, .. } = self {
            pipe.release_to(recv_offset);
        }
    }

    fn close(&mut self) {
        if let Self::Open { pipe, .. } = self {
            pipe.close();
        }
        *self = Self::Closed;
    }

    fn poll_pending(&mut self, stream_id: StreamId, pending: &mut VecDeque<EngineInput>) {
        let Self::Open {
            dir,
            pipe,
            pending_pull,
            finish_queued,
        } = self
        else {
            return;
        };
        if let Some(pull) = pending_pull.take() {
            if let Some(mut grant) = pipe.reserve_at(pull.offset, pull.max_len) {
                let mut bytes = vec![0; grant.len()];
                let _ = grant.read_exact(&mut bytes);
                pending.push_back(EngineInput::OutboundData {
                    stream_id,
                    dir: *dir,
                    offset: grant.offset(),
                    bytes,
                });
                return;
            }
            if pipe.writer_finished() && pipe.all_sent() {
                if !*finish_queued {
                    *finish_queued = true;
                    pending.push_back(EngineInput::OutboundFinished {
                        stream_id,
                        dir: *dir,
                        final_offset: pipe.sent_offset(),
                    });
                }
                return;
            }
            *pending_pull = Some(pull);
            return;
        }

        if pipe.writer_finished() && pipe.all_sent() && !*finish_queued {
            *finish_queued = true;
            pending.push_back(EngineInput::OutboundFinished {
                stream_id,
                dir: *dir,
                final_offset: pipe.sent_offset(),
            });
        }
    }
}

enum InboundIo {
    Open(pipe::PipeWriter<QlError>),
    Closed,
}

impl InboundIo {
    fn new(pipe: pipe::PipeWriter<QlError>) -> Self {
        Self::Open(pipe)
    }

    fn write_or_cancel(
        &mut self,
        stream_id: StreamId,
        dir: Direction,
        bytes: &[u8],
        pending: &mut VecDeque<EngineInput>,
    ) {
        let Self::Open(pipe) = self else {
            pending.push_back(EngineInput::ResetInbound {
                stream_id,
                dir,
                code: ResetCode::Cancelled,
            });
            return;
        };
        match pipe.try_write(bytes) {
            Ok(n) if n == bytes.len() => {}
            Ok(_) | Err(_) => {
                pipe.close();
                *self = Self::Closed;
                pending.push_back(EngineInput::ResetInbound {
                    stream_id,
                    dir,
                    code: ResetCode::Cancelled,
                });
            }
        }
    }

    fn finish(&mut self) {
        if let Self::Open(pipe) = self {
            pipe.finish();
        }
        *self = Self::Closed;
    }

    fn fail(&mut self, error: QlError) {
        if let Self::Open(pipe) = self {
            pipe.fail(error);
        }
        *self = Self::Closed;
    }

    fn close(&mut self) {
        if let Self::Open(pipe) = self {
            pipe.close();
        }
        *self = Self::Closed;
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
    fn new(config: crate::runtime::RuntimeConfig, peer: Option<crate::Peer>) -> Self {
        let engine = Engine::new(config, peer);
        let next_timer = engine.next_deadline();
        Self {
            engine,
            pending_inputs: VecDeque::new(),
            next_timer,
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
                request_pipe,
                accepted,
                start,
                config,
            } => {
                let open_id = OpenId(self.next_open_id);
                self.next_open_id = self.next_open_id.wrapping_add(1);
                self.pending_opens.insert(
                    open_id,
                    PendingOpen {
                        request_pipe,
                        start_tx: start,
                        accepted_tx: accepted,
                    },
                );
                self.push_input(EngineInput::OpenStream {
                    open_id,
                    request_head,
                    config,
                });
            }
            RuntimeCommand::AcceptStream {
                stream_id,
                response_head,
                response_pipe,
            } => {
                if let Some(DriverStreamIo::Responder { response, .. }) = self.streams.get_mut(&stream_id)
                {
                    *response = ResponderResponseIo::Streaming(OutboundIo::new(Direction::Response, response_pipe));
                }
                self.push_input(EngineInput::AcceptStream {
                    stream_id,
                    response_head,
                });
            }
            RuntimeCommand::RejectStream { stream_id, code } => {
                if let Some(DriverStreamIo::Responder { response, .. }) = self.streams.get_mut(&stream_id)
                {
                    *response = ResponderResponseIo::Rejected;
                }
                self.push_input(EngineInput::RejectStream { stream_id, code });
            }
            RuntimeCommand::PollStream { stream_id } => self.poll_stream(stream_id),
            RuntimeCommand::AdvanceInboundCredit {
                stream_id,
                dir,
                amount,
            } => self.push_input(EngineInput::InboundConsumed {
                stream_id,
                dir,
                amount,
            }),
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
                if let Some(DriverStreamIo::Initiator { pending_accept, .. }) = self.streams.get_mut(&stream_id)
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
        let mut state = DriverState::new(self.config, self.platform.load_peer().await);
        let mut in_flight: Option<InFlightWrite<'_>> = None;

        loop {
            if let Some(input) = state.pending_inputs.pop_front() {
                let now = Instant::now();
                let pending_inputs = &mut state.pending_inputs;
                let next_timer = &mut state.next_timer;
                let pending_opens = &mut state.pending_opens;
                let streams = &mut state.streams;
                state.engine.run_tick(now, input, &self.platform, &mut |output| {
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

            match self.next_driver_event(state.next_timer, in_flight.as_mut()).await {
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
                let (response_reader, response_writer) = pipe::pipe(self.config.pipe_size_bytes);
                streams.insert(
                    stream_id,
                    DriverStreamIo::Initiator {
                        request: OutboundIo::new(Direction::Request, pending.request_pipe),
                        response: InboundIo::new(response_writer),
                        pending_accept: PendingAcceptState::Waiting(PendingAcceptDelivery {
                            tx: pending.accepted_tx,
                            response_reader,
                        }),
                    },
                );
            }
            EngineOutput::OpenAccepted {
                stream_id,
                response_head,
                ..
            } => {
                let Some(DriverStreamIo::Initiator { pending_accept, .. }) = streams.get_mut(&stream_id)
                else {
                    return;
                };
                match std::mem::replace(pending_accept, PendingAcceptState::Resolved) {
                    PendingAcceptState::Waiting(delivery) => {
                        let _ = delivery.tx.send(Ok(AcceptedStreamDelivery {
                            stream_id,
                            response_head,
                            response: delivery.response_reader,
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
                let Some(DriverStreamIo::Initiator { pending_accept, .. }) = streams.get_mut(&stream_id)
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
            } => {
                let (request_reader, request_writer) = pipe::pipe(self.config.pipe_size_bytes);
                streams.insert(
                    stream_id,
                    DriverStreamIo::Responder {
                        request: InboundIo::new(request_writer),
                        response: ResponderResponseIo::Pending,
                    },
                );
                self.platform.handle_inbound(HandlerEvent::Stream(InboundStream {
                    stream_id,
                    request_head,
                    request: InboundByteStream::new(
                        stream_id,
                        Direction::Request,
                        request_reader,
                        runtime_tx.clone(),
                    ),
                    respond_to: StreamResponder::new(
                        stream_id,
                        self.config.pipe_size_bytes,
                        runtime_tx.clone(),
                    ),
                }));
            }
            EngineOutput::InboundData {
                stream_id,
                dir,
                bytes,
            } => {
                if let Some(stream) = streams.get_mut(&stream_id) {
                    if let Some(inbound) = stream.inbound_mut(dir) {
                        inbound.write_or_cancel(stream_id, dir, &bytes, pending_inputs);
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
            EngineOutput::NeedOutboundData {
                stream_id,
                dir,
                offset,
                max_len,
            } => {
                if let Some(stream) = streams.get_mut(&stream_id) {
                    if let Some(outbound) = stream.outbound_mut(dir) {
                        outbound.set_pending_pull(offset, max_len);
                    }
                }
                poll_stream(streams, pending_inputs, stream_id);
            }
            EngineOutput::ReleaseOutboundThrough {
                stream_id,
                dir,
                recv_offset,
            } => {
                if let Some(stream) = streams.get_mut(&stream_id) {
                    if let Some(outbound) = stream.outbound_mut(dir) {
                        outbound.release_to(recv_offset);
                    }
                }
            }
            EngineOutput::OutboundClosed { stream_id, dir }
            | EngineOutput::OutboundFailed {
                stream_id, dir, ..
            } => {
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
            DriverStreamIo::Initiator { request, .. } => request.poll_pending(stream_id, pending_inputs),
            DriverStreamIo::Responder { response, .. } => {
                if let ResponderResponseIo::Streaming(outbound) = response {
                    outbound.poll_pending(stream_id, pending_inputs);
                }
            }
        }
    }
}
