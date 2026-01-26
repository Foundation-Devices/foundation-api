use std::{
    cmp::{Ordering, Reverse},
    collections::{BinaryHeap, HashMap, VecDeque},
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_channel::{Receiver, Sender, WeakSender};
use bc_components::{Signer, ARID, XID};
use bc_envelope::Envelope;

use crate::envelope_wire::{
    decode_ql_message, encode_ql_message, DecodeErrContext, EncodeQlConfig, MessageKind, QlMessage,
};

pub type PlatformFuture<'a> = Pin<Box<dyn Future<Output = Result<(), QlError>> + 'a>>;

pub trait QlPlatform {
    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_>;
    fn sleep_ms(&self, ms: u64) -> PlatformFuture<'_>;
}

#[derive(Debug)]
pub enum QlError {
    Cancelled,
    Protocol,
    SendFailed,
    Timeout,
    Decode(crate::envelope_wire::DecodeError),
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
    pub message: QlMessage,
    pub respond_to: Responder,
}

#[derive(Debug, Clone)]
pub struct Responder {
    id: ARID,
    recipient: XID,
    tx: Sender<ExecutorEvent>,
}

impl Responder {
    pub fn id(&self) -> ARID {
        self.id
    }

    pub async fn respond(
        self,
        payload: Envelope,
        config: EncodeQlConfig,
        signer: &dyn Signer,
    ) -> Result<(), QlError> {
        assert_eq!(config.recipient, self.recipient, "not same recipient");
        let bytes = encode_ql_message(
            MessageKind::Response,
            self.id,
            EncodeQlConfig {
                signing_key: config.signing_key,
                recipient: self.recipient,
                valid_for: config.valid_for,
            },
            payload,
            signer,
        );
        self.tx
            .send(ExecutorEvent::SendResponse { bytes })
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
            id: request.message.header.id,
            recipient: request.message.header.sender_xid(),
            tx: request.tx,
        };
        Ok(IncomingRequest {
            message: request.message,
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
                    id: request.message.header.id,
                    recipient: request.message.header.sender_xid(),
                    tx: request.tx,
                };
                Poll::Ready(Some(Ok(IncomingRequest {
                    message: request.message,
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
    message: QlMessage,
    tx: Sender<ExecutorEvent>,
}

#[derive(Debug)]
enum ExecutorEvent {
    SendRequest {
        id: ARID,
        bytes: Vec<u8>,
        respond_to: oneshot::Sender<Result<QlMessage, QlError>>,
        config: RequestConfig,
    },
    SendResponse {
        bytes: Vec<u8>,
    },
    Incoming {
        message: QlMessage,
    },
    IncomingDecodeError {
        context: DecodeErrContext,
    },
}

#[derive(Debug, Clone)]
pub struct ExecutorHandle {
    tx: Sender<ExecutorEvent>,
}

impl ExecutorHandle {
    pub async fn request(
        &self,
        payload: Envelope,
        encode_config: EncodeQlConfig,
        signer: &dyn Signer,
        request_config: RequestConfig,
    ) -> Result<QlMessage, QlError> {
        let id = ARID::new();
        let bytes = encode_ql_message(MessageKind::Request, id, encode_config, payload, signer);
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ExecutorEvent::SendRequest {
                id,
                bytes,
                respond_to: tx,
                config: request_config,
            })
            .await
            .map_err(|_| QlError::Cancelled)?;
        rx.await.map_err(|_| QlError::Cancelled)?
    }

    pub async fn send_incoming(&self, bytes: Vec<u8>) -> Result<(), QlError> {
        match decode_ql_message(&bytes) {
            Ok(message) => self
                .tx
                .send(ExecutorEvent::Incoming { message })
                .await
                .map_err(|_| QlError::Cancelled),
            Err(context) => {
                let _ = self
                    .tx
                    .send(ExecutorEvent::IncomingDecodeError { context })
                    .await;
                Ok(())
            }
        }
    }
}

pub struct Executor<P> {
    platform: P,
    rx: Receiver<ExecutorEvent>,
    tx: WeakSender<ExecutorEvent>,
    config: ExecutorConfig,
    incoming: Sender<InboundRequest>,
}

struct ExecutorState<'a> {
    pending: HashMap<ARID, PendingEntry>,
    timeouts: BinaryHeap<Reverse<TimeoutEntry>>,
    outbound: VecDeque<OutboundBytes>,
    in_flight: Option<InFlightWrite<'a>>,
}

struct OutboundBytes {
    id: Option<ARID>,
    bytes: Vec<u8>,
}

struct InFlightWrite<'a> {
    id: Option<ARID>,
    future: PlatformFuture<'a>,
}

struct PendingEntry {
    tx: oneshot::Sender<Result<QlMessage, QlError>>,
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

impl<P> Executor<P>
where
    P: QlPlatform,
{
    pub fn new(
        platform: P,
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
                    state.in_flight = Some(InFlightWrite {
                        id: message.id,
                        future: self.platform.write_message(message.bytes),
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
                        id,
                        bytes,
                        respond_to,
                        config,
                    } => {
                        let effective_timeout =
                            config.timeout.unwrap_or(self.config.default_timeout);
                        if effective_timeout.is_zero() {
                            let _ = respond_to.send(Err(QlError::Timeout));
                            continue;
                        }
                        let deadline = Instant::now() + effective_timeout;
                        state.pending.insert(id, PendingEntry { tx: respond_to });
                        state.timeouts.push(Reverse(TimeoutEntry { deadline, id }));
                        state.outbound.push_back(OutboundBytes {
                            id: Some(id),
                            bytes,
                        });
                    }
                    ExecutorEvent::SendResponse { bytes } => {
                        state.outbound.push_back(OutboundBytes { id: None, bytes });
                    }
                    ExecutorEvent::Incoming { message } => match message.header.kind {
                        MessageKind::Response => {
                            if let Some(entry) = state.pending.remove(&message.header.id) {
                                let _ = entry.tx.send(Ok(message));
                            }
                        }
                        MessageKind::Request => {
                            let Some(tx) = self.tx.upgrade() else { return };
                            let _ = self.incoming.send(InboundRequest { message, tx }).await;
                        }
                        MessageKind::Event => {}
                    },
                    ExecutorEvent::IncomingDecodeError { context } => {
                        let Some(header) = context.header else {
                            continue;
                        };
                        if header.kind == MessageKind::Response {
                            if let Some(entry) = state.pending.remove(&header.id) {
                                let _ = entry.tx.send(Err(QlError::Decode(context.error)));
                            }
                        }
                    }
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
            if let Some(pending) = state.pending.remove(&entry.id) {
                let _ = pending.tx.send(Err(QlError::Timeout));
            }
        }
    }

    fn next_timeout_sleep(state: &ExecutorState<'_>) -> Option<Duration> {
        let Reverse(entry) = state.timeouts.peek()?;
        let now = Instant::now();
        Some(entry.deadline.saturating_duration_since(now))
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use crate::quantum_link::QuantumLinkIdentity;

    struct TestPlatform {
        tx: Sender<Vec<u8>>,
    }

    impl TestPlatform {
        fn new() -> (Self, Receiver<Vec<u8>>) {
            let (tx, rx) = async_channel::unbounded();
            (Self { tx }, rx)
        }
    }

    impl QlPlatform for TestPlatform {
        fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_> {
            let tx = self.tx.clone();
            Box::pin(async move { tx.send(message).await.map_err(|_| QlError::Cancelled) })
        }

        fn sleep_ms(&self, ms: u64) -> PlatformFuture<'_> {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(ms)).await;
                Ok(())
            })
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_response_round_trip() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let (platform, outbound_rx) = TestPlatform::new();
                let config = ExecutorConfig {
                    default_timeout: Duration::from_millis(50),
                };
                let (mut core, handle, _incoming) = Executor::new(platform, config);
                tokio::task::spawn_local(async move { core.run().await });

                let requester = QuantumLinkIdentity::generate();
                let responder = QuantumLinkIdentity::generate();
                let recipient_xid: XID = responder.xid_document.clone().into();
                let signing_key = requester
                    .xid_document
                    .verification_key()
                    .expect("missing signing key")
                    .clone();
                let signer = requester.private_keys.clone().expect("missing signer");
                let payload = Envelope::new("ping");
                let encrypted_payload = payload.encrypt_to_recipient(
                    responder
                        .xid_document
                        .encryption_key()
                        .expect("missing encryption key"),
                );

                let response_task = tokio::task::spawn_local({
                    let handle = handle.clone();
                    async move {
                        handle
                            .request(
                                encrypted_payload,
                                EncodeQlConfig {
                                    signing_key,
                                    recipient: recipient_xid,
                                    valid_for: Duration::from_secs(60),
                                },
                                &signer,
                                RequestConfig::default(),
                            )
                            .await
                    }
                });

                let outbound = outbound_rx.recv().await.expect("no outbound request");
                let outbound_message = decode_ql_message(&outbound).expect("decode outbound");
                assert_eq!(outbound_message.header.kind, MessageKind::Request);
                let request_id = outbound_message.header.id;

                let response_signing_key = responder
                    .xid_document
                    .verification_key()
                    .expect("missing signing key")
                    .clone();
                let response_signer = responder.private_keys.as_ref().expect("missing signer");
                let response_payload = Envelope::new("pong");
                let response_encrypted = response_payload.encrypt_to_recipient(
                    requester
                        .xid_document
                        .encryption_key()
                        .expect("missing encryption key"),
                );
                let response_bytes = encode_ql_message(
                    MessageKind::Response,
                    request_id,
                    EncodeQlConfig {
                        signing_key: response_signing_key,
                        recipient: outbound_message.header.sender_xid(),
                        valid_for: Duration::from_secs(60),
                    },
                    response_encrypted,
                    response_signer,
                );
                handle.send_incoming(response_bytes).await.unwrap();

                let response = response_task.await.unwrap().unwrap();
                assert_eq!(response.header.kind, MessageKind::Response);
                assert_eq!(response.header.id, request_id);
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_timeout_returns_error() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let (platform, _outbound_rx) = TestPlatform::new();
                let config = ExecutorConfig {
                    default_timeout: Duration::from_millis(5),
                };
                let (mut core, handle, _incoming) = Executor::new(platform, config);
                tokio::task::spawn_local(async move { core.run().await });

                let requester = QuantumLinkIdentity::generate();
                let recipient_xid: XID = requester.xid_document.clone().into();
                let signing_key = requester
                    .xid_document
                    .verification_key()
                    .expect("missing signing key")
                    .clone();
                let signer = requester.private_keys.clone().expect("missing signer");
                let payload = Envelope::new("timeout");
                let encrypted_payload = payload.encrypt_to_recipient(
                    requester
                        .xid_document
                        .encryption_key()
                        .expect("missing encryption key"),
                );
                let result = handle
                    .request(
                        encrypted_payload,
                        EncodeQlConfig {
                            signing_key,
                            recipient: recipient_xid,
                            valid_for: Duration::from_secs(60),
                        },
                        &signer,
                        RequestConfig {
                            timeout: Some(Duration::from_millis(1)),
                        },
                    )
                    .await;

                assert!(matches!(result, Err(QlError::Timeout)));
            })
            .await;
    }
}
