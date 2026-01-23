use std::{
    cmp::{Ordering, Reverse},
    collections::{BinaryHeap, HashMap, VecDeque},
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_channel::{Receiver, Sender, WeakSender};
use bc_components::ARID;
use bc_envelope::{RequestBehavior, ResponseBehavior};
use gstp::{SealedRequest, SealedResponse};

pub type PlatformFuture<'a> = Pin<Box<dyn Future<Output = Result<(), QlError>> + 'a>>;

pub trait QlPlatform {
    fn write_message(&self, message: OutboundMessage) -> PlatformFuture<'_>;
    fn sleep_ms(&self, ms: u64) -> PlatformFuture<'_>;
}

#[derive(Debug)]
pub enum QlError {
    Cancelled,
    Protocol,
    SendFailed,
    Timeout,
}

#[derive(Debug)]
pub enum OutboundMessage {
    Request(SealedRequest),
    Response(SealedResponse),
}

#[derive(Debug)]
pub enum IncomingMessage {
    Request(SealedRequest),
    Response(SealedResponse),
}

#[derive(Debug, Clone, Copy)]
pub struct RequestConfig {
    pub timeout: Option<Duration>,
}

impl Default for RequestConfig {
    fn default() -> Self {
        Self { timeout: None }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ExecutorConfig {
    pub default_timeout: Duration,
}

#[derive(Debug)]
pub struct IncomingRequest {
    pub request: SealedRequest,
    pub respond_to: Responder,
}

#[derive(Debug, Clone)]
pub struct Responder {
    id: ARID,
    tx: Sender<ExecutorEvent>,
}

impl Responder {
    pub fn id(&self) -> ARID {
        self.id
    }

    pub async fn respond(self, response: SealedResponse) -> Result<(), QlError> {
        if response.id() != Some(self.id) {
            return Err(QlError::Protocol);
        }
        self.tx
            .send(ExecutorEvent::SendResponse { response })
            .await
            .map_err(|_| QlError::Cancelled)
    }
}

#[derive(Debug)]
pub struct IncomingRequestStream {
    rx: Receiver<InboundRequest>,
}

impl IncomingRequestStream {
    pub async fn next(&mut self) -> Result<IncomingRequest, QlError> {
        let request = self.rx.recv().await.map_err(|_| QlError::Cancelled)?;
        let responder = Responder {
            id: request.request.id(),
            tx: request.tx,
        };
        Ok(IncomingRequest {
            request: request.request,
            respond_to: responder,
        })
    }
}

impl futures_lite::Stream for IncomingRequestStream {
    type Item = Result<IncomingRequest, QlError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let rx = unsafe { self.as_mut().map_unchecked_mut(|s| &mut s.rx) };
        match rx.poll_next(cx) {
            Poll::Ready(Some(request)) => {
                let responder = Responder {
                    id: request.request.id(),
                    tx: request.tx,
                };
                Poll::Ready(Some(Ok(IncomingRequest {
                    request: request.request,
                    respond_to: responder,
                })))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug)]
struct InboundRequest {
    request: SealedRequest,
    tx: Sender<ExecutorEvent>,
}

#[derive(Debug)]
enum ExecutorEvent {
    SendRequest {
        request: SealedRequest,
        respond_to: oneshot::Sender<Result<SealedResponse, QlError>>,
        config: RequestConfig,
    },
    SendResponse {
        response: SealedResponse,
    },
    Incoming {
        message: IncomingMessage,
    },
}

#[derive(Debug, Clone)]
pub struct ExecutorHandle {
    tx: Sender<ExecutorEvent>,
}

impl ExecutorHandle {
    pub async fn request(
        &self,
        request: SealedRequest,
        config: RequestConfig,
    ) -> Result<SealedResponse, QlError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ExecutorEvent::SendRequest {
                request,
                respond_to: tx,
                config,
            })
            .await
            .map_err(|_| QlError::Cancelled)?;
        rx.await.map_err(|_| QlError::Cancelled)?
    }

    pub async fn send_incoming(&self, message: IncomingMessage) -> Result<(), QlError> {
        self.tx
            .send(ExecutorEvent::Incoming { message })
            .await
            .map_err(|_| QlError::Cancelled)
    }
}

pub struct Executor {
    rx: Receiver<ExecutorEvent>,
    tx: WeakSender<ExecutorEvent>,
    platform: Box<dyn QlPlatform>,
    config: ExecutorConfig,
    incoming: Sender<InboundRequest>,
}

struct ExecutorState<'a> {
    pending: HashMap<ARID, PendingEntry>,
    timeouts: BinaryHeap<Reverse<TimeoutEntry>>,
    outbound: VecDeque<OutboundMessage>,
    in_flight: Option<InFlightWrite<'a>>,
}

struct InFlightWrite<'a> {
    id: Option<ARID>,
    future: PlatformFuture<'a>,
}

struct PendingEntry {
    tx: oneshot::Sender<Result<SealedResponse, QlError>>,
}

#[derive(Debug, Clone)]
struct TimeoutEntry {
    deadline: Instant,
    id: ARID,
}

impl PartialEq for TimeoutEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline
    }
}

impl Eq for TimeoutEntry {}

impl PartialOrd for TimeoutEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimeoutEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.deadline.cmp(&other.deadline)
    }
}

enum LoopStep {
    Event(Result<ExecutorEvent, async_channel::RecvError>),
    WriteDone {
        id: Option<ARID>,
        result: Result<(), QlError>,
    },
    Timeout,
}

impl Executor {
    pub fn new(
        platform: Box<dyn QlPlatform>,
        config: ExecutorConfig,
    ) -> (Self, ExecutorHandle, IncomingRequestStream) {
        let (tx, rx) = async_channel::unbounded();
        let (incoming_tx, incoming_rx) = async_channel::unbounded();
        (
            Self {
                rx,
                tx: tx.downgrade(),
                platform,
                config,
                incoming: incoming_tx,
            },
            ExecutorHandle { tx },
            IncomingRequestStream { rx: incoming_rx },
        )
    }

    pub async fn run<'a>(&'a mut self) {
        let mut state = ExecutorState {
            pending: HashMap::new(),
            timeouts: BinaryHeap::new(),
            outbound: VecDeque::new(),
            in_flight: None,
        };

        loop {
            Self::process_timeouts(&mut state);

            if state.in_flight.is_none() {
                if let Some(message) = state.outbound.pop_front() {
                    let id = match &message {
                        OutboundMessage::Request(request) => Some(request.id()),
                        OutboundMessage::Response(response) => response.id(),
                    };
                    state.in_flight = Some(InFlightWrite {
                        id,
                        future: self.platform.write_message(message),
                    });
                }
            }

            let step = {
                let recv_future = self.rx.recv();
                futures_lite::pin!(recv_future);

                let mut sleep_future = Self::next_timeout_sleep(&state)
                    .map(|duration| self.platform.sleep_ms(duration.as_millis() as u64));

                futures_lite::future::poll_fn(|cx| {
                    if let Some(in_flight) = state.in_flight.as_mut() {
                        if let Poll::Ready(result) = in_flight.future.as_mut().poll(cx) {
                            return Poll::Ready(LoopStep::WriteDone {
                                id: in_flight.id,
                                result,
                            });
                        }
                    }

                    if let Some(sleep_future) = sleep_future.as_mut() {
                        if let Poll::Ready(_result) = sleep_future.as_mut().poll(cx) {
                            return Poll::Ready(LoopStep::Timeout);
                        }
                    }

                    match recv_future.as_mut().poll(cx) {
                        Poll::Ready(event) => Poll::Ready(LoopStep::Event(event)),
                        Poll::Pending => Poll::Pending,
                    }
                })
                .await
            };

            match step {
                LoopStep::Event(Ok(event)) => match event {
                    ExecutorEvent::SendRequest {
                        request,
                        respond_to,
                        config,
                    } => {
                        let effective_timeout =
                            config.timeout.unwrap_or(self.config.default_timeout);
                        if effective_timeout.is_zero() {
                            let _ = respond_to.send(Err(QlError::Timeout));
                            continue;
                        }
                        let id = request.id();
                        let deadline = Instant::now() + effective_timeout;
                        state.pending.insert(id, PendingEntry { tx: respond_to });
                        state.timeouts.push(Reverse(TimeoutEntry { deadline, id }));
                        state.outbound.push_back(OutboundMessage::Request(request));
                    }
                    ExecutorEvent::SendResponse { response } => {
                        state
                            .outbound
                            .push_back(OutboundMessage::Response(response));
                    }
                    ExecutorEvent::Incoming { message } => match message {
                        IncomingMessage::Response(response) => {
                            if let Some(id) = response.id() {
                                if let Some(entry) = state.pending.remove(&id) {
                                    let _ = entry.tx.send(Ok(response));
                                }
                            }
                        }
                        IncomingMessage::Request(request) => {
                            let Some(tx) = self.tx.upgrade() else { return };
                            let _ = self.incoming.send(InboundRequest { request, tx }).await;
                        }
                    },
                },
                LoopStep::Event(Err(_)) => break,
                LoopStep::WriteDone { id, result } => {
                    state.in_flight = None;
                    if let Err(e) = result {
                        if let Some(id) = id {
                            if let Some(entry) = state.pending.remove(&id) {
                                let _ = entry.tx.send(Err(e));
                            }
                        }
                    }
                }
                LoopStep::Timeout => {
                    Self::process_timeouts(&mut state);
                }
            }
        }
    }

    fn process_timeouts(state: &mut ExecutorState<'_>) {
        let now = Instant::now();
        while let Some(Reverse(entry)) = state.timeouts.peek().cloned() {
            if entry.deadline > now {
                break;
            }
            state.timeouts.pop();
            if !state.pending.contains_key(&entry.id) {
                continue;
            }
            if let Some(pending) = state.pending.remove(&entry.id) {
                let _ = pending.tx.send(Err(QlError::Timeout));
            }
        }
    }

    fn next_timeout_sleep(state: &ExecutorState<'_>) -> Option<Duration> {
        let Reverse(entry) = state.timeouts.peek()?.clone();
        let now = Instant::now();
        Some(entry.deadline.saturating_duration_since(now))
    }
}
