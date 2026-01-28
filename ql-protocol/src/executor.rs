use std::{
    cmp::{Ordering, Reverse},
    collections::{BinaryHeap, HashMap, VecDeque},
    future::Future,
    pin::{pin, Pin},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_channel::{Receiver, Sender, WeakSender};
use bc_components::{EncryptedMessage, ARID, XID};

use super::wire::{
    decode_ql_message, encode_ql_message, DecodeErrContext, MessageKind, QlHeader, QlMessage,
};

pub type PlatformFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub trait ExecutorPlatform {
    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), ExecutorError>>;
    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()>;
}

#[derive(Debug)]
pub enum ExecutorError {
    Cancelled,
    Protocol,
    SessionReset,
    SendFailed,
    Timeout,
    Decode(super::wire::DecodeError),
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
pub struct InboundRequest {
    pub message: QlMessage,
    pub respond_to: Responder,
}

#[derive(Debug)]
pub struct InboundEvent {
    pub message: QlMessage,
}

#[derive(Debug)]
pub enum HandlerEvent {
    Request(InboundRequest),
    Event(InboundEvent),
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

    pub fn recipient(&self) -> XID {
        self.recipient
    }

    pub fn respond(
        self,
        header: QlHeader,
        payload: EncryptedMessage,
    ) -> Result<(), ExecutorError> {
        let bytes = encode_ql_message(header, payload);
        self.tx
            .send_blocking(ExecutorEvent::SendResponse { bytes })
            .map_err(|_| ExecutorError::Cancelled)
    }
}

#[derive(Debug)]
pub struct HandlerStream {
    rx: Receiver<HandlerEvent>,
}

impl HandlerStream {
    pub async fn next(&mut self) -> Result<HandlerEvent, ExecutorError> {
        self.rx.recv().await.map_err(|_| ExecutorError::Cancelled)
    }
}

impl futures_lite::Stream for HandlerStream {
    type Item = Result<HandlerEvent, ExecutorError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let rx = unsafe { self.as_mut().map_unchecked_mut(|s| &mut s.rx) };
        match rx.poll_next(cx) {
            Poll::Ready(Some(event)) => Poll::Ready(Some(Ok(event))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug)]
enum ExecutorEvent {
    SendRequest {
        id: ARID,
        recipient: XID,
        bytes: Vec<u8>,
        respond_to: oneshot::Sender<Result<QlMessage, ExecutorError>>,
        config: RequestConfig,
    },
    SendEvent {
        bytes: Vec<u8>,
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

pub struct ExecutorResponse {
    rx: oneshot::Receiver<Result<QlMessage, ExecutorError>>,
}

impl std::future::Future for ExecutorResponse {
    type Output = Result<QlMessage, ExecutorError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        pin!(&mut self.rx)
            .poll(cx)
            .map(|result| result.unwrap_or(Err(ExecutorError::Cancelled)))
    }
}

impl ExecutorHandle {
    pub fn request(
        &self,
        header: QlHeader,
        payload: EncryptedMessage,
        request_config: RequestConfig,
    ) -> ExecutorResponse {
        let recipient = header.recipient;
        let id = header.id;
        let bytes = encode_ql_message(header, payload);
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_blocking(ExecutorEvent::SendRequest {
                id,
                bytes,
                respond_to: tx,
                recipient,
                config: request_config,
            })
            .unwrap();
        ExecutorResponse { rx }
    }

    pub fn send_event(
        &self,
        header: QlHeader,
        payload: EncryptedMessage,
    ) {
        let tx = self.tx.clone();
        let bytes = encode_ql_message(header, payload);
        tx.send_blocking(ExecutorEvent::SendEvent { bytes })
            .unwrap();
    }

    pub fn send_message(
        &self,
        header: QlHeader,
        payload: EncryptedMessage,
    ) {
        let tx = self.tx.clone();
        let bytes = encode_ql_message(header, payload);
        tx.send_blocking(ExecutorEvent::SendEvent { bytes })
            .unwrap();
    }

    pub fn send_incoming(&self, bytes: Vec<u8>) -> Result<(), ExecutorError> {
        match decode_ql_message(&bytes) {
            Ok(message) => self
                .tx
                .send_blocking(ExecutorEvent::Incoming { message })
                .map_err(|_| ExecutorError::Cancelled),
            Err(context) => {
                let _ = self
                    .tx
                    .send_blocking(ExecutorEvent::IncomingDecodeError { context });
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
    incoming: Sender<HandlerEvent>,
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
    future: PlatformFuture<'a, Result<(), ExecutorError>>,
}

struct PendingEntry {
    tx: oneshot::Sender<Result<QlMessage, ExecutorError>>,
    recipient: XID,
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
        result: Result<(), ExecutorError>,
    },
    Timeout,
}

impl<P> Executor<P>
where
    P: ExecutorPlatform,
{
    pub fn new(platform: P, config: ExecutorConfig) -> (Self, ExecutorHandle, HandlerStream) {
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
            HandlerStream { rx: incoming_rx },
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

                let mut sleep_future =
                    Self::next_timeout_sleep(&state).map(|duration| self.platform.sleep(duration));

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
                        recipient,
                        config,
                    } => {
                        let effective_timeout =
                            config.timeout.unwrap_or(self.config.default_timeout);
                        if effective_timeout.is_zero() {
                            let _ = respond_to.send(Err(ExecutorError::Timeout));
                            continue;
                        }
                        let deadline = Instant::now() + effective_timeout;
                        state.pending.insert(
                            id,
                            PendingEntry {
                                tx: respond_to,
                                recipient,
                            },
                        );
                        state.timeouts.push(Reverse(TimeoutEntry { deadline, id }));
                        state.outbound.push_back(OutboundBytes {
                            id: Some(id),
                            bytes,
                        });
                    }
                    ExecutorEvent::SendEvent { bytes } => {
                        state.outbound.push_back(OutboundBytes { id: None, bytes });
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
                            let responder = Responder {
                                id: message.header.id,
                                recipient: message.header.sender,
                                tx,
                            };
                            let _ = self
                                .incoming
                                .send(HandlerEvent::Request(InboundRequest {
                                    message,
                                    respond_to: responder,
                                }))
                                .await;
                        }
                        MessageKind::SessionReset => {
                            Self::cancel_pending_for_sender(&mut state, message.header.sender);
                            let _ = self
                                .incoming
                                .send(HandlerEvent::Event(InboundEvent { message }))
                                .await;
                        }
                        MessageKind::Event | MessageKind::Pairing => {
                            let _ = self
                                .incoming
                                .send(HandlerEvent::Event(InboundEvent { message }))
                                .await;
                        }
                    },
                    ExecutorEvent::IncomingDecodeError { context } => {
                        let Some(header) = context.header else {
                            continue;
                        };
                        if header.kind == MessageKind::Response {
                            if let Some(entry) = state.pending.remove(&header.id) {
                                let _ = entry.tx.send(Err(ExecutorError::Decode(context.error)));
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
                let _ = pending.tx.send(Err(ExecutorError::Timeout));
            }
        }
    }

    fn cancel_pending_for_sender(state: &mut ExecutorState<'_>, sender: XID) {
        for (_id, entry) in state
            .pending
            .extract_if(|_, entry| entry.recipient == sender)
        {
            let _ = entry.tx.send(Err(ExecutorError::SessionReset));
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
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::ql::encrypt;
    use crate::test_identity::TestIdentity;

    struct TestPlatform {
        tx: Sender<Vec<u8>>,
    }

    impl TestPlatform {
        fn new() -> (Self, Receiver<Vec<u8>>) {
            let (tx, rx) = async_channel::unbounded();
            (Self { tx }, rx)
        }
    }

    impl ExecutorPlatform for TestPlatform {
        fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), ExecutorError>> {
            let tx = self.tx.clone();
            Box::pin(async move { tx.send(message).await.map_err(|_| ExecutorError::Cancelled) })
        }

        fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()> {
            Box::pin(async move {
                tokio::time::sleep(duration).await;
            })
        }
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }

    fn build_header(
        kind: MessageKind,
        id: ARID,
        sender: XID,
        recipient: XID,
        valid_until: u64,
    ) -> QlHeader {
        QlHeader {
            kind,
            id,
            sender,
            recipient,
            valid_until,
            kem_ct: None,
            signature: None,
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

                let requester = TestIdentity::generate();
                let responder = TestIdentity::generate();
                let recipient_xid = responder.xid;
                let valid_until = now_secs().saturating_add(60);
                let payload = encrypt::encrypt_test_payload(b"ping");
                let request_id = ARID::new();
                let request_header =
                    build_header(MessageKind::Request, request_id, requester.xid, recipient_xid, valid_until);

                let response_task = tokio::task::spawn_local({
                    let handle = handle.clone();
                        async move {
                            handle
                                .request(request_header, payload, RequestConfig::default())
                                .await
                        }
                    });

                let outbound = outbound_rx.recv().await.expect("no outbound request");
                let outbound_message = decode_ql_message(&outbound).expect("decode outbound");
                assert_eq!(outbound_message.header.kind, MessageKind::Request);
                let request_id = outbound_message.header.id;

                let response_payload = encrypt::encrypt_test_payload(b"pong");
                let response_header = build_header(
                    MessageKind::Response,
                    request_id,
                    responder.xid,
                    outbound_message.header.sender,
                    now_secs().saturating_add(60),
                );
                let response_bytes = encode_ql_message(response_header, response_payload);
                handle.send_incoming(response_bytes).unwrap();

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

                let requester = TestIdentity::generate();
                let recipient_xid = requester.xid;
                let valid_until = now_secs().saturating_add(60);
                let payload = encrypt::encrypt_test_payload(b"timeout");
                let request_id = ARID::new();
                let request_header =
                    build_header(MessageKind::Request, request_id, requester.xid, recipient_xid, valid_until);
                let result = handle
                    .request(
                        request_header,
                        payload,
                        RequestConfig {
                            timeout: Some(Duration::from_millis(1)),
                        },
                    )
                    .await;

                assert!(matches!(result, Err(ExecutorError::Timeout)));
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn event_is_forwarded() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let (platform, _outbound_rx) = TestPlatform::new();
                let config = ExecutorConfig {
                    default_timeout: Duration::from_secs(1),
                };
                let (mut core, handle, mut handler_stream) = Executor::new(platform, config);
                tokio::task::spawn_local(async move { core.run().await });

                let sender = TestIdentity::generate();
                let recipient = TestIdentity::generate();
                let recipient_xid = recipient.xid;
                let event_id = ARID::new();
                let payload = encrypt::encrypt_test_payload(b"event");
                let event_header = build_header(
                    MessageKind::Event,
                    event_id,
                    sender.xid,
                    recipient_xid,
                    now_secs().saturating_add(60),
                );
                let event_bytes = encode_ql_message(event_header, payload);

                handle.send_incoming(event_bytes).unwrap();

                let event = handler_stream.next().await.unwrap();
                match event {
                    HandlerEvent::Event(event) => {
                        assert_eq!(event.message.header.kind, MessageKind::Event);
                        assert_eq!(event.message.header.id, event_id);
                    }
                    HandlerEvent::Request(_) => panic!("unexpected request"),
                }
            })
            .await;
    }

}
