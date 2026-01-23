use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use async_channel::{Receiver, Sender, WeakSender};
use bc_components::ARID;
use bc_envelope::{RequestBehavior, ResponseBehavior};
use gstp::{SealedRequest, SealedResponse};

pub type PlatformFuture<'a> = Pin<Box<dyn Future<Output = Result<(), QlError>> + 'a>>;

pub trait QlPlatform {
    fn write_message(&self, message: OutboundMessage) -> PlatformFuture<'_>;
}

#[derive(Debug)]
pub enum QlError {
    Cancelled,
    Protocol,
    SendFailed,
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
    pub async fn request(&self, request: SealedRequest) -> Result<SealedResponse, QlError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ExecutorEvent::SendRequest {
                request,
                respond_to: tx,
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
    pending: HashMap<ARID, oneshot::Sender<Result<SealedResponse, QlError>>>,
    incoming: Sender<InboundRequest>,
}

struct InFlightWrite<'a> {
    id: Option<ARID>,
    future: PlatformFuture<'a>,
}

enum LoopStep {
    Event(Result<ExecutorEvent, async_channel::RecvError>),
    WriteDone {
        id: Option<ARID>,
        result: Result<(), QlError>,
    },
}

impl Executor {
    pub fn new(platform: Box<dyn QlPlatform>) -> (Self, ExecutorHandle, IncomingRequestStream) {
        let (tx, rx) = async_channel::unbounded();
        let (incoming_tx, incoming_rx) = async_channel::unbounded();
        (
            Self {
                rx,
                tx: tx.downgrade(),
                platform,
                pending: HashMap::new(),
                incoming: incoming_tx,
            },
            ExecutorHandle { tx },
            IncomingRequestStream { rx: incoming_rx },
        )
    }

    pub async fn run<'a>(&'a mut self) {
        let mut outbound: VecDeque<OutboundMessage> = VecDeque::new();
        let mut in_flight: Option<InFlightWrite<'a>> = None;

        loop {
            if in_flight.is_none() {
                if let Some(message) = outbound.pop_front() {
                    let id = match &message {
                        OutboundMessage::Request(request) => Some(request.id()),
                        OutboundMessage::Response(response) => response.id(),
                    };
                    in_flight = Some(InFlightWrite {
                        id,
                        future: self.platform.write_message(message),
                    });
                }
            }

            let step = {
                let recv_future = self.rx.recv();
                futures_lite::pin!(recv_future);

                futures_lite::future::poll_fn(|cx| {
                    if let Some(in_flight) = in_flight.as_mut() {
                        if let std::task::Poll::Ready(result) = in_flight.future.as_mut().poll(cx) {
                            return std::task::Poll::Ready(LoopStep::WriteDone {
                                id: in_flight.id,
                                result,
                            });
                        }
                    }

                    match recv_future.as_mut().poll(cx) {
                        std::task::Poll::Ready(event) => {
                            std::task::Poll::Ready(LoopStep::Event(event))
                        }
                        std::task::Poll::Pending => std::task::Poll::Pending,
                    }
                })
                .await
            };

            match step {
                LoopStep::Event(Ok(event)) => match event {
                    ExecutorEvent::SendRequest {
                        request,
                        respond_to,
                    } => {
                        let id = request.id();
                        self.pending.insert(id, respond_to);
                        outbound.push_back(OutboundMessage::Request(request));
                    }
                    ExecutorEvent::SendResponse { response } => {
                        outbound.push_back(OutboundMessage::Response(response));
                    }
                    ExecutorEvent::Incoming { message } => match message {
                        IncomingMessage::Response(response) => {
                            // all responses must have an id
                            if let Some(id) = response.id() {
                                if let Some(tx) = self.pending.remove(&id) {
                                    let _ = tx.send(Ok(response));
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
                    in_flight = None;
                    if let Err(e) = result {
                        if let Some(id) = id {
                            if let Some(tx) = self.pending.remove(&id) {
                                let _ = tx.send(Err(e));
                            }
                        }
                    }
                }
            }
        }
    }
}
