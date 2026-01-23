use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    pin::Pin,
};

use async_channel::{Receiver, Sender};
use dcbor::CBOR;
use futures_lite::future;

pub trait QlCodec: Into<CBOR> + TryFrom<CBOR, Error = dcbor::Error> {}

impl<T> QlCodec for T where T: Into<CBOR> + TryFrom<CBOR, Error = dcbor::Error> {}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

type PlatformFuture<'a> = BoxFuture<'a, Result<(), QlError>>;

pub trait QlPlatform {
    fn write_bytes(&self, data: Vec<u8>) -> PlatformFuture<'_>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QlErrorCode {
    Protocol = 1,
    UnsupportedApi = 2,
    Cbor = 3,
    Timeout = 4,
    Cancelled = 5,
}

impl From<QlErrorCode> for CBOR {
    fn from(value: QlErrorCode) -> Self {
        CBOR::from(value as u64)
    }
}

impl TryFrom<CBOR> for QlErrorCode {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let value: u64 = cbor.try_into()?;
        match value {
            1 => Ok(QlErrorCode::Protocol),
            2 => Ok(QlErrorCode::UnsupportedApi),
            3 => Ok(QlErrorCode::Cbor),
            4 => Ok(QlErrorCode::Timeout),
            5 => Ok(QlErrorCode::Cancelled),
            _ => Err("unknown error code".into()),
        }
    }
}

#[derive(Debug)]
pub enum QlError {
    Protocol,
    UnsupportedApi,
    Cbor,
    Timeout,
    Cancelled,
}

impl From<QlErrorCode> for QlError {
    fn from(value: QlErrorCode) -> Self {
        match value {
            QlErrorCode::Protocol => QlError::Protocol,
            QlErrorCode::UnsupportedApi => QlError::UnsupportedApi,
            QlErrorCode::Cbor => QlError::Cbor,
            QlErrorCode::Timeout => QlError::Timeout,
            QlErrorCode::Cancelled => QlError::Cancelled,
        }
    }
}

pub trait RequestResponse: QlCodec {
    const ID: u64;
    type Response: QlCodec;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Request = 0,
    Response = 1,
}

impl TryFrom<u8> for FrameKind {
    type Error = QlError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(FrameKind::Request),
            1 => Ok(FrameKind::Response),
            _ => Err(QlError::Protocol),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub kind: FrameKind,
    pub api_id: u64,
    pub msg_id: u64,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(1 + 8 + 8 + self.payload.len());
        data.push(self.kind as u8);
        data.extend_from_slice(&self.api_id.to_le_bytes());
        data.extend_from_slice(&self.msg_id.to_le_bytes());
        data.extend_from_slice(&self.payload);
        data
    }

    pub fn decode(data: &[u8]) -> Result<Self, QlError> {
        if data.len() < 17 {
            return Err(QlError::Protocol);
        }
        let kind = FrameKind::try_from(data[0])?;
        let api_id = u64::from_le_bytes(data[1..9].try_into().map_err(|_| QlError::Protocol)?);
        let msg_id = u64::from_le_bytes(data[9..17].try_into().map_err(|_| QlError::Protocol)?);
        let payload = data[17..].to_vec();
        Ok(Self {
            kind,
            api_id,
            msg_id,
            payload,
        })
    }
}

#[derive(Debug, Clone)]
struct ResponseEnvelope {
    ok: bool,
    value: CBOR,
}

impl ResponseEnvelope {
    fn ok(value: CBOR) -> Self {
        Self { ok: true, value }
    }

    fn err(code: QlErrorCode) -> Self {
        Self {
            ok: false,
            value: code.into(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let data = vec![CBOR::from(self.ok), self.value.clone()];
        CBOR::from(data).to_cbor_data()
    }

    fn decode(data: &[u8]) -> Result<Result<CBOR, QlErrorCode>, QlError> {
        let cbor = CBOR::try_from_data(data).map_err(|_| QlError::Cbor)?;
        let array = cbor.try_into_array().map_err(|_| QlError::Cbor)?;
        if array.len() != 2 {
            return Err(QlError::Protocol);
        }
        let ok: bool = array[0].clone().try_into().map_err(|_| QlError::Cbor)?;
        if ok {
            Ok(Ok(array[1].clone()))
        } else {
            let code: QlErrorCode = array[1].clone().try_into().map_err(|_| QlError::Cbor)?;
            Ok(Err(code))
        }
    }
}

#[derive(Debug)]
pub struct IncomingRequest<M: RequestResponse> {
    pub message: M,
    pub response: PendingResponse<M>,
}

#[derive(Debug)]
pub struct PendingResponse<M: RequestResponse> {
    api_id: u64,
    msg_id: u64,
    events: Sender<ExecutorEvent>,
    default_response: fn() -> Result<<M as RequestResponse>::Response, QlErrorCode>,
    responded: bool,
}

impl<M: RequestResponse> PendingResponse<M> {
    pub fn msg_id(&self) -> u64 {
        self.msg_id
    }

    pub async fn respond(self, response: M::Response) -> Result<(), QlError> {
        self.respond_raw(ResponseEnvelope::ok(response.into()).encode())
            .await
    }

    pub async fn respond_error(self, code: QlErrorCode) -> Result<(), QlError> {
        self.respond_raw(ResponseEnvelope::err(code).encode()).await
    }

    async fn respond_raw(mut self, payload: Vec<u8>) -> Result<(), QlError> {
        self.responded = true;
        self.events
            .send(ExecutorEvent::SendResponse {
                api_id: self.api_id,
                msg_id: self.msg_id,
                payload,
            })
            .await
            .map_err(|_| QlError::Cancelled)
    }
}

impl<M: RequestResponse> Drop for PendingResponse<M> {
    fn drop(&mut self) {
        if self.responded {
            return;
        }

        let payload = match (self.default_response)() {
            Ok(response) => ResponseEnvelope::ok(response.into()).encode(),
            Err(code) => ResponseEnvelope::err(code).encode(),
        };

        let _ = self.events.send_blocking(ExecutorEvent::SendResponse {
            api_id: self.api_id,
            msg_id: self.msg_id,
            payload,
        });
    }
}

#[derive(Debug)]
pub struct IncomingRequestStream<M: RequestResponse> {
    rx: Receiver<InboundRequest>,
    default_response: fn() -> Result<<M as RequestResponse>::Response, QlErrorCode>,
}

impl<M: RequestResponse> IncomingRequestStream<M> {
    pub async fn next(&self) -> Option<Result<IncomingRequest<M>, QlError>> {
        let request = self.rx.recv().await.ok()?;
        let cbor = match CBOR::try_from_data(&request.payload) {
            Ok(cbor) => cbor,
            Err(_) => {
                let _ = request
                    .events
                    .send(ExecutorEvent::SendResponse {
                        api_id: request.api_id,
                        msg_id: request.msg_id,
                        payload: ResponseEnvelope::err(QlErrorCode::Cbor).encode(),
                    })
                    .await;
                return Some(Err(QlError::Cbor));
            }
        };
        let message = match M::try_from(cbor) {
            Ok(message) => message,
            Err(_) => {
                let _ = request
                    .events
                    .send(ExecutorEvent::SendResponse {
                        api_id: request.api_id,
                        msg_id: request.msg_id,
                        payload: ResponseEnvelope::err(QlErrorCode::Cbor).encode(),
                    })
                    .await;
                return Some(Err(QlError::Cbor));
            }
        };
        let response = PendingResponse {
            api_id: request.api_id,
            msg_id: request.msg_id,
            events: request.events,
            default_response: self.default_response,
            responded: false,
        };
        Some(Ok(IncomingRequest { message, response }))
    }
}

#[derive(Debug)]
struct InboundRequest {
    api_id: u64,
    msg_id: u64,
    payload: Vec<u8>,
    events: Sender<ExecutorEvent>,
}

#[derive(Debug)]
enum ExecutorEvent {
    SendRequest {
        api_id: u64,
        payload: Vec<u8>,
        respond_to: oneshot::Sender<Vec<u8>>,
    },
    SendResponse {
        api_id: u64,
        msg_id: u64,
        payload: Vec<u8>,
    },
    RegisterHandler {
        api_id: u64,
        tx: Sender<InboundRequest>,
    },
    IncomingFrame {
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct ExecutorHandle {
    tx: Sender<ExecutorEvent>,
}

impl ExecutorHandle {
    pub fn register_request_handler<M>(
        &self,
        capacity: usize,
        default_response: fn() -> Result<M::Response, QlErrorCode>,
    ) -> Result<IncomingRequestStream<M>, QlError>
    where
        M: RequestResponse,
    {
        let (tx, rx) = async_channel::bounded(capacity);
        self.tx
            .send_blocking(ExecutorEvent::RegisterHandler { api_id: M::ID, tx })
            .map_err(|_| QlError::Cancelled)?;
        Ok(IncomingRequestStream {
            rx,
            default_response,
        })
    }

    pub async fn request_response<M>(&self, msg: M) -> Result<M::Response, QlError>
    where
        M: RequestResponse,
    {
        let payload = msg.into().to_cbor_data();
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ExecutorEvent::SendRequest {
                api_id: M::ID,
                payload,
                respond_to: tx,
            })
            .await
            .map_err(|_| QlError::Cancelled)?;
        let payload = rx.await.map_err(|_| QlError::Cancelled)?;
        let response = ResponseEnvelope::decode(&payload)?;
        match response {
            Ok(cbor) => M::Response::try_from(cbor).map_err(|_| QlError::Cbor),
            Err(code) => Err(code.into()),
        }
    }

    pub async fn send_incoming(&self, data: Vec<u8>) -> Result<(), QlError> {
        self.tx
            .send(ExecutorEvent::IncomingFrame { data })
            .await
            .map_err(|_| QlError::Cancelled)
    }
}

pub struct QlExecutor {
    tx: Sender<ExecutorEvent>,
    rx: Receiver<ExecutorEvent>,
    handlers: HashMap<u64, Sender<InboundRequest>>,
    pending: HashMap<u64, oneshot::Sender<Vec<u8>>>,
    next_msg_id: u64,
}

struct OutboundFrame {
    msg_id: Option<u64>,
    data: Vec<u8>,
}

struct InFlightWrite<'a> {
    msg_id: Option<u64>,
    future: PlatformFuture<'a>,
}

enum LoopStep {
    Event(Result<ExecutorEvent, async_channel::RecvError>),
    WriteDone {
        result: Result<(), QlError>,
        msg_id: Option<u64>,
    },
}

impl QlExecutor {
    pub fn new(buffer: usize) -> (Self, ExecutorHandle) {
        let (tx, rx) = async_channel::bounded(buffer);
        (
            Self {
                tx: tx.clone(),
                rx,
                handlers: HashMap::new(),
                pending: HashMap::new(),
                next_msg_id: 1,
            },
            ExecutorHandle { tx },
        )
    }

    pub async fn run<'a>(&'a mut self, platform: &'a dyn QlPlatform) {
        let mut outbound: VecDeque<OutboundFrame> = VecDeque::new();
        let mut in_flight: Option<InFlightWrite<'a>> = None;

        loop {
            if in_flight.is_none() {
                if let Some(frame) = outbound.pop_front() {
                    in_flight = Some(InFlightWrite {
                        msg_id: frame.msg_id,
                        future: platform.write_bytes(frame.data),
                    });
                }
            }

            let step = {
                let recv_future = self.rx.recv();
                futures_lite::pin!(recv_future);

                future::poll_fn(|cx| {
                    if let Some(in_flight) = in_flight.as_mut() {
                        if let std::task::Poll::Ready(result) = in_flight.future.as_mut().poll(cx) {
                            return std::task::Poll::Ready(LoopStep::WriteDone {
                                result,
                                msg_id: in_flight.msg_id,
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
                        api_id,
                        payload,
                        respond_to,
                    } => {
                        let msg_id = self.next_msg_id;
                        self.next_msg_id = self.next_msg_id.wrapping_add(1);
                        self.pending.insert(msg_id, respond_to);
                        let frame = Frame {
                            kind: FrameKind::Request,
                            api_id,
                            msg_id,
                            payload,
                        };
                        outbound.push_back(OutboundFrame {
                            msg_id: Some(msg_id),
                            data: frame.encode(),
                        });
                    }
                    ExecutorEvent::SendResponse {
                        api_id,
                        msg_id,
                        payload,
                    } => {
                        let frame = Frame {
                            kind: FrameKind::Response,
                            api_id,
                            msg_id,
                            payload,
                        };
                        outbound.push_back(OutboundFrame {
                            msg_id: None,
                            data: frame.encode(),
                        });
                    }
                    ExecutorEvent::RegisterHandler { api_id, tx } => {
                        self.handlers.insert(api_id, tx);
                    }
                    ExecutorEvent::IncomingFrame { data } => {
                        let frame = match Frame::decode(&data) {
                            Ok(frame) => frame,
                            Err(_) => continue,
                        };
                        match frame.kind {
                            FrameKind::Request => {
                                if let Some(handler) = self.handlers.get(&frame.api_id) {
                                    let result = handler
                                        .send(InboundRequest {
                                            api_id: frame.api_id,
                                            msg_id: frame.msg_id,
                                            payload: frame.payload,
                                            events: self.tx.clone(),
                                        })
                                        .await;
                                    if result.is_err() {
                                        let response = Frame {
                                            kind: FrameKind::Response,
                                            api_id: frame.api_id,
                                            msg_id: frame.msg_id,
                                            payload: ResponseEnvelope::err(QlErrorCode::Cancelled)
                                                .encode(),
                                        };
                                        outbound.push_back(OutboundFrame {
                                            msg_id: None,
                                            data: response.encode(),
                                        });
                                    }
                                } else {
                                    let response = Frame {
                                        kind: FrameKind::Response,
                                        api_id: frame.api_id,
                                        msg_id: frame.msg_id,
                                        payload: ResponseEnvelope::err(QlErrorCode::UnsupportedApi)
                                            .encode(),
                                    };
                                    outbound.push_back(OutboundFrame {
                                        msg_id: None,
                                        data: response.encode(),
                                    });
                                }
                            }
                            FrameKind::Response => {
                                if let Some(tx) = self.pending.remove(&frame.msg_id) {
                                    let _ = tx.send(frame.payload);
                                }
                            }
                        }
                    }
                },
                LoopStep::Event(Err(_)) => break,
                LoopStep::WriteDone { result, msg_id } => {
                    in_flight = None;
                    if result.is_err() {
                        if let Some(msg_id) = msg_id {
                            if let Some(tx) = self.pending.remove(&msg_id) {
                                let _ =
                                    tx.send(ResponseEnvelope::err(QlErrorCode::Protocol).encode());
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::Pin};

    use super::*;

    fn run_test<F>(f: F)
    where
        F: for<'a> FnOnce(
            &'a async_executor::LocalExecutor<'static>,
        ) -> Pin<Box<dyn Future<Output = ()> + 'a>>,
    {
        let executor = async_executor::LocalExecutor::<'static>::new();
        futures_lite::future::block_on(async move {
            let executor_ref = &executor;
            executor.run(f(executor_ref)).await;
        });
    }

    #[derive(Debug, Clone, PartialEq)]
    struct Ping(u64);

    impl From<Ping> for CBOR {
        fn from(value: Ping) -> Self {
            CBOR::from(value.0)
        }
    }

    impl TryFrom<CBOR> for Ping {
        type Error = dcbor::Error;

        fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
            let value: u64 = cbor.try_into()?;
            Ok(Ping(value))
        }
    }

    impl RequestResponse for Ping {
        const ID: u64 = 1;
        type Response = Pong;
    }

    fn default_ping() -> Result<Pong, QlErrorCode> {
        Err(QlErrorCode::Cancelled)
    }

    #[derive(Debug, Clone, PartialEq)]
    struct Pong(u64);

    impl From<Pong> for CBOR {
        fn from(value: Pong) -> Self {
            CBOR::from(value.0)
        }
    }

    impl TryFrom<CBOR> for Pong {
        type Error = dcbor::Error;

        fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
            let value: u64 = cbor.try_into()?;
            Ok(Pong(value))
        }
    }

    struct TestPlatform {
        tx: Sender<Vec<u8>>,
    }

    impl TestPlatform {
        fn new(buffer: usize) -> (Self, Receiver<Vec<u8>>) {
            let (tx, rx) = async_channel::bounded(buffer);
            (Self { tx }, rx)
        }
    }

    impl QlPlatform for TestPlatform {
        fn write_bytes(&self, data: Vec<u8>) -> PlatformFuture<'_> {
            let tx = self.tx.clone();
            Box::pin(async move { tx.send(data).await.map_err(|_| QlError::Cancelled) })
        }
    }

    #[test]
    fn request_response_round_trip() {
        run_test(|executor| {
            Box::pin(async move {
                let (platform, outbound_rx) = TestPlatform::new(10);
                let (mut core, handle) = QlExecutor::new(10);

                let _executor_task = executor.spawn(async move { core.run(&platform).await });

                let request_task = executor.spawn({
                    let handle = handle.clone();
                    async move { handle.request_response(Ping(7)).await }
                });

                let outbound = outbound_rx.recv().await.unwrap();
                let frame = Frame::decode(&outbound).unwrap();
                assert_eq!(frame.kind, FrameKind::Request);
                assert_eq!(frame.api_id, Ping::ID);

                let response_payload = ResponseEnvelope::ok(Pong(9).into()).encode();
                let response_frame = Frame {
                    kind: FrameKind::Response,
                    api_id: frame.api_id,
                    msg_id: frame.msg_id,
                    payload: response_payload,
                };
                handle.send_incoming(response_frame.encode()).await.unwrap();

                let response = request_task.await.unwrap();
                assert_eq!(response, Pong(9));
            })
        });
    }

    #[test]
    fn handler_round_trip() {
        run_test(|executor| {
            Box::pin(async move {
                let (platform, outbound_rx) = TestPlatform::new(10);
                let (mut core, handle) = QlExecutor::new(10);

                let _executor_task = executor.spawn(async move { core.run(&platform).await });

                let handler_stream = handle
                    .register_request_handler::<Ping>(10, default_ping)
                    .unwrap();
                let handler_task = executor.spawn(async move {
                    if let Some(Ok(request)) = handler_stream.next().await {
                        request
                            .response
                            .respond(Pong(request.message.0 + 1))
                            .await
                            .unwrap();
                    }
                });

                let request_payload = CBOR::from(Ping(10)).to_cbor_data();
                let request_frame = Frame {
                    kind: FrameKind::Request,
                    api_id: Ping::ID,
                    msg_id: 42,
                    payload: request_payload,
                };
                handle.send_incoming(request_frame.encode()).await.unwrap();

                let outbound = outbound_rx.recv().await.unwrap();
                let frame = Frame::decode(&outbound).unwrap();
                assert_eq!(frame.kind, FrameKind::Response);
                assert_eq!(frame.api_id, Ping::ID);
                assert_eq!(frame.msg_id, 42);

                let response = ResponseEnvelope::decode(&frame.payload).unwrap().unwrap();
                let response = Pong::try_from(response).unwrap();
                assert_eq!(response, Pong(11));

                handler_task.await;
            })
        });
    }

    #[test]
    fn handler_drop_sends_default() {
        run_test(|executor| {
            Box::pin(async move {
                let (platform, outbound_rx) = TestPlatform::new(10);
                let (mut core, handle) = QlExecutor::new(10);

                let _executor_task = executor.spawn(async move { core.run(&platform).await });

                let handler_stream = handle
                    .register_request_handler::<Ping>(10, default_ping)
                    .unwrap();
                let handler_task = executor.spawn(async move {
                    if let Some(Ok(_request)) = handler_stream.next().await {
                        // Drop without responding to trigger default.
                    }
                });

                let request_payload = CBOR::from(Ping(5)).to_cbor_data();
                let request_frame = Frame {
                    kind: FrameKind::Request,
                    api_id: Ping::ID,
                    msg_id: 7,
                    payload: request_payload,
                };
                handle.send_incoming(request_frame.encode()).await.unwrap();

                handler_task.await;

                let outbound = outbound_rx.recv().await.unwrap();
                let frame = Frame::decode(&outbound).unwrap();
                assert_eq!(frame.kind, FrameKind::Response);
                assert_eq!(frame.api_id, Ping::ID);
                assert_eq!(frame.msg_id, 7);

                let response = ResponseEnvelope::decode(&frame.payload).unwrap();
                let err = response.err().unwrap();
                assert_eq!(err, QlErrorCode::Cancelled);
            })
        });
    }
}
