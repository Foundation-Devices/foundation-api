use std::{cell::RefCell, future::Ready, rc::Rc, time::Duration};

use bytes::{Buf, BufMut, Bytes};
use futures_lite::StreamExt;
use ql_rpc::{RouteId, StreamCloseCode};
use ql_wire::RouteId as WireRouteId;

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
struct BytesValue(Vec<u8>);

impl ql_rpc::RpcCodec for BytesValue {
    type Error = core::convert::Infallible;

    fn encode_value<B: BufMut + ?Sized>(&self, out: &mut B) {
        out.put_slice(&self.0);
    }

    fn decode_value<B: Buf>(bytes: &mut B) -> Result<Self, Self::Error> {
        Ok(Self(bytes.copy_to_bytes(bytes.remaining()).to_vec()))
    }
}

struct Echo;

impl ql_rpc::request::Request for Echo {
    const METHOD: RouteId = RouteId::from_u32(51);
    type Error = core::convert::Infallible;
    type Request = BytesValue;
    type Response = BytesValue;
}

struct Feed;

impl ql_rpc::subscription::Subscription for Feed {
    const METHOD: RouteId = RouteId::from_u32(52);
    type Error = core::convert::Infallible;
    type Request = BytesValue;
    type Event = BytesValue;
}

struct Download;

impl ql_rpc::request_with_progress::RequestWithProgress for Download {
    const METHOD: RouteId = RouteId::from_u32(53);
    type Error = core::convert::Infallible;
    type Request = BytesValue;
    type Progress = BytesValue;
    type Response = BytesValue;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_request_round_trips() {
    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            let request: BytesValue = read_rpc_value(inbound.reader).await;
            assert_eq!(
                inbound.route_id,
                to_wire_route_id(<Echo as ql_rpc::request::Request>::METHOD)
            );
            assert_eq!(request, BytesValue(b"hello".to_vec()));

            let mut encoded = Vec::new();
            ql_rpc::request::encode_response::<Echo>(&BytesValue(b"world".to_vec()), &mut encoded);
            let mut writer = inbound.writer;
            writer.write(Bytes::from(encoded)).await.unwrap();
            writer.finish();
        });

        let rpc = pair.handle(Side::A).rpc();
        let response = rpc
            .request::<Echo>(&BytesValue(b"hello".to_vec()))
            .await
            .unwrap();
        assert_eq!(response, BytesValue(b"world".to_vec()));

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_router_handles_request() {
    #[derive(Clone)]
    struct RouterState {
        seen: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl crate::rpc::RequestHandler<Echo> for RouterState {
        type Future<'a>
            = Ready<Result<BytesValue, StreamCloseCode>>
        where
            Self: 'a;

        fn handle<'a>(&'a self, request: BytesValue) -> Self::Future<'a> {
            self.seen.borrow_mut().push(request.0);
            std::future::ready(Ok(BytesValue(b"world".to_vec())))
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let seen = Rc::new(RefCell::new(Vec::new()));
        let router = crate::rpc::Router::builder()
            .request::<Echo>()
            .build(RouterState { seen: seen.clone() });

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            router.handle(inbound).await;
        });

        let rpc = pair.handle(Side::A).rpc();
        let response = rpc
            .request::<Echo>(&BytesValue(b"hello".to_vec()))
            .await
            .unwrap();
        assert_eq!(response, BytesValue(b"world".to_vec()));
        assert_eq!(&*seen.borrow(), &[b"hello".to_vec()]);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_router_enforces_max_request_bytes() {
    struct LimitedState;

    impl crate::rpc::RequestHandler<Echo> for LimitedState {
        type Future<'a>
            = Ready<Result<BytesValue, StreamCloseCode>>
        where
            Self: 'a;

        fn handle<'a>(&'a self, request: BytesValue) -> Self::Future<'a> {
            std::future::ready(Ok(request))
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let router = crate::rpc::Router::builder()
            .max_request_bytes(4)
            .request::<Echo>()
            .build(LimitedState);

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            router.handle(inbound).await;
        });

        let rpc = pair.handle(Side::A).rpc();
        let response = rpc.request::<Echo>(&BytesValue(b"hello".to_vec())).await;
        assert!(matches!(
            response,
            Err(crate::rpc::RpcError::Closed(code)) if code == StreamCloseCode::LIMIT
        ));

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_subscription_streams_events() {
    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            let request: BytesValue = read_rpc_value(inbound.reader).await;
            assert_eq!(
                inbound.route_id,
                to_wire_route_id(<Feed as ql_rpc::subscription::Subscription>::METHOD)
            );
            assert_eq!(request, BytesValue(b"watch".to_vec()));

            let mut encoded = Vec::new();
            ql_rpc::subscription::encode_item::<Feed>(&BytesValue(b"one".to_vec()), &mut encoded);
            ql_rpc::subscription::encode_item::<Feed>(&BytesValue(b"two".to_vec()), &mut encoded);
            ql_rpc::subscription::encode_end(&mut encoded);

            let mut writer = inbound.writer;
            writer.write(Bytes::from(encoded)).await.unwrap();
            writer.finish();
        });

        let rpc = pair.handle(Side::A).rpc();
        let mut subscription = rpc
            .subscribe::<Feed>(&BytesValue(b"watch".to_vec()))
            .await
            .unwrap();
        assert_eq!(
            subscription.next().await.unwrap().unwrap(),
            BytesValue(b"one".to_vec())
        );
        assert_eq!(
            subscription.next().await.unwrap().unwrap(),
            BytesValue(b"two".to_vec())
        );
        assert!(subscription.next().await.is_none());

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_request_with_progress_supports_progress_then_await() {
    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            let request: BytesValue = read_rpc_value(inbound.reader).await;
            assert_eq!(
                inbound.route_id,
                to_wire_route_id(
                    <Download as ql_rpc::request_with_progress::RequestWithProgress>::METHOD
                )
            );
            assert_eq!(request, BytesValue(b"logo".to_vec()));

            let mut encoded = Vec::new();
            ql_rpc::request_with_progress::encode_progress::<Download>(
                &BytesValue(b"10".to_vec()),
                &mut encoded,
            );
            ql_rpc::request_with_progress::encode_progress::<Download>(
                &BytesValue(b"90".to_vec()),
                &mut encoded,
            );
            ql_rpc::request_with_progress::encode_response::<Download>(
                &BytesValue(b"done".to_vec()),
                &mut encoded,
            );

            let mut writer = inbound.writer;
            writer.write(Bytes::from(encoded)).await.unwrap();
            writer.finish();
        });

        let rpc = pair.handle(Side::A).rpc();
        let mut download = rpc
            .request_with_progress::<Download>(&BytesValue(b"logo".to_vec()))
            .await
            .unwrap();

        assert_eq!(download.progress().await, Some(BytesValue(b"10".to_vec())));
        assert_eq!(download.progress().await, Some(BytesValue(b"90".to_vec())));
        assert_eq!(download.progress().await, None);
        assert_eq!(download.await.unwrap(), BytesValue(b"done".to_vec()));

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

async fn read_rpc_value<T>(mut reader: crate::ByteReader) -> T
where
    T: ql_rpc::RpcCodec,
    T::Error: std::fmt::Debug,
{
    let mut value_reader = ql_rpc::ValueReader::<T>::new();

    loop {
        match value_reader.advance().unwrap() {
            ql_rpc::ReadValueStep::Value(value) => return value,
            ql_rpc::ReadValueStep::NeedMore(next) => value_reader = next,
        }

        match reader.read_chunk().await.unwrap() {
            Some(chunk) => value_reader = value_reader.push(chunk),
            None => panic!("truncated rpc value"),
        }
    }
}

fn to_wire_route_id(route_id: RouteId) -> WireRouteId {
    WireRouteId::from_u32(route_id.into_inner())
}
