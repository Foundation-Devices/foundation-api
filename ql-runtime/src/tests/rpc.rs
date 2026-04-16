use std::{
    cell::RefCell,
    rc::Rc,
    str::Utf8Error,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use futures_lite::StreamExt;
use ql_rpc::{
    DownloadResponder, DownloadWriter, Response, RouteId, StreamCloseCode, SubscriptionResponder,
};
use ql_wire::RouteId as WireRouteId;

use super::*;
use crate::{QlStream, StreamWriter};

struct Echo;

impl ql_rpc::request::Request for Echo {
    const ROUTE: RouteId = RouteId::from_u32(51);

    type Error = Utf8Error;

    type Request = String;
    type Response = String;
}

struct Feed;

impl ql_rpc::subscription::Subscription for Feed {
    const ROUTE: RouteId = RouteId::from_u32(52);
    type Error = core::convert::Infallible;
    type Request = Vec<u8>;
    type Event = Vec<u8>;
}

struct Download;

impl ql_rpc::request_with_progress::RequestWithProgress for Download {
    const ROUTE: RouteId = RouteId::from_u32(53);
    type Error = core::convert::Infallible;
    type Request = Vec<u8>;
    type Progress = Vec<u8>;
    type Response = Vec<u8>;
}

struct BlobDownload;

impl ql_rpc::download::Download for BlobDownload {
    const ROUTE: RouteId = RouteId::from_u32(54);
    type Error = core::convert::Infallible;
    type Request = Vec<u8>;
    type ResponseHeader = Vec<u8>;
}

fn assert_send<T: Send>(value: T) -> T {
    value
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_request_round_trips() {
    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            let request: Vec<u8> = read_rpc_value(inbound.reader).await;
            assert_eq!(
                inbound.route_id,
                to_wire_route_id(<Echo as ql_rpc::request::Request>::ROUTE)
            );
            assert_eq!(request, b"hello".to_vec());

            let mut encoded = Vec::new();
            ql_rpc::request::encode_response::<Echo>(&"world".into(), &mut encoded);
            let mut writer = inbound.writer;
            writer.write(Bytes::from(encoded)).await.unwrap();
            writer.finish().await.unwrap();
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let response = rpc.request::<Echo>(&"hello".into()).await.unwrap();
        assert_eq!(response, "world");

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
        seen: Rc<RefCell<Vec<String>>>,
    }

    impl crate::rpc::RequestHandler<Echo, QlStream> for RouterState {
        fn handle(self, request: String, response: Response<String, StreamWriter>) {
            let seen = self.seen.clone();
            tokio::task::spawn_local(async move {
                seen.borrow_mut().push(request);
                let _ = response.respond("world".into()).await;
            });
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let seen = Rc::new(RefCell::new(Vec::new()));

        let router =
            ql_rpc::Router::<_, QlStream, crate::rpc::LocalSpawn>::builder(crate::rpc::LocalSpawn)
                .request::<Echo>()
                .build(RouterState { seen: seen.clone() });

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(inbound) {
                fut.await
            }
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let response = rpc.request::<Echo>(&"hello".into()).await.unwrap();
        assert_eq!(response, "world");
        assert_eq!(&*seen.borrow(), &["hello".to_string()]);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_router_handles_subscription() {
    #[derive(Clone)]
    struct RouterState {
        seen: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl crate::rpc::SubscriptionHandler<Feed, QlStream> for RouterState {
        fn handle(
            self,
            request: Vec<u8>,
            mut response: SubscriptionResponder<Vec<u8>, StreamWriter>,
        ) {
            let seen = self.seen.clone();
            tokio::task::spawn_local(async move {
                seen.borrow_mut().push(request);
                let _ = response.send(b"one".to_vec()).await;
                let _ = response.send(b"two".to_vec()).await;
                let _ = response.finish().await;
            });
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);

        let seen = Rc::new(RefCell::new(Vec::new()));
        let router =
            ql_rpc::Router::<_, QlStream, crate::rpc::LocalSpawn>::builder(crate::rpc::LocalSpawn)
                .subscription::<Feed>()
                .build(RouterState { seen: seen.clone() });

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(inbound) {
                fut.await;
            }
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let mut subscription = rpc.subscribe::<Feed>(&b"watch".to_vec()).await.unwrap();
        assert_eq!(subscription.next().await.unwrap().unwrap(), b"one".to_vec());
        assert_eq!(subscription.next().await.unwrap().unwrap(), b"two".to_vec());
        assert!(subscription.next().await.is_none());
        assert_eq!(seen.borrow().as_slice(), &[b"watch".to_vec()]);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_send_router_handles_request() {
    #[derive(Clone)]
    struct RouterState {
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl crate::rpc::RequestHandler<Echo, QlStream> for RouterState {
        fn handle(self, request: String, response: crate::rpc::Response<String, StreamWriter>) {
            let seen = self.seen.clone();
            tokio::task::spawn(async move {
                seen.lock().unwrap().push(request);
                let _ = response.respond("world".into()).await;
            });
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let router =
            ql_rpc::Router::<_, QlStream, crate::rpc::SendSpawn>::builder(crate::rpc::SendSpawn)
                .request::<Echo>()
                .build(RouterState { seen: seen.clone() });

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(inbound) {
                let fut = assert_send(fut);
                fut.await
            }
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let response = rpc.request::<Echo>(&"hello".into()).await.unwrap();
        assert_eq!(response, "world");
        assert_eq!(&*seen.lock().unwrap(), &["hello".to_string()]);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_router_enforces_max_request_bytes() {
    #[derive(Clone)]
    struct LimitedState;

    impl crate::rpc::RequestHandler<Echo, crate::QlStream> for LimitedState {
        fn handle(
            self,
            request: String,
            response: crate::rpc::Response<String, crate::StreamWriter>,
        ) {
            tokio::task::spawn_local(async move {
                let _ = response.respond(request).await;
            });
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let router =
            ql_rpc::Router::<_, QlStream, crate::rpc::LocalSpawn>::builder(crate::rpc::LocalSpawn)
                .max_request_bytes(4)
                .request::<Echo>()
                .build(LimitedState);

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(inbound) {
                fut.await
            }
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let response = rpc.request::<Echo>(&"hello".to_string()).await;
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
            let request: Vec<u8> = read_rpc_value(inbound.reader).await;
            assert_eq!(
                inbound.route_id,
                to_wire_route_id(<Feed as ql_rpc::subscription::Subscription>::ROUTE)
            );
            assert_eq!(request, b"watch".to_vec());

            let mut encoded = Vec::new();
            ql_rpc::subscription::encode_item::<Feed>(&b"one".to_vec(), &mut encoded);
            ql_rpc::subscription::encode_item::<Feed>(&b"two".to_vec(), &mut encoded);

            let mut writer = inbound.writer;
            writer.write(Bytes::from(encoded)).await.unwrap();
            writer.finish().await.unwrap();
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let mut subscription = rpc.subscribe::<Feed>(&b"watch".to_vec()).await.unwrap();
        assert_eq!(subscription.next().await.unwrap().unwrap(), b"one".to_vec());
        assert_eq!(subscription.next().await.unwrap().unwrap(), b"two".to_vec());
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
            let request: Vec<u8> = read_rpc_value(inbound.reader).await;
            assert_eq!(
                inbound.route_id,
                to_wire_route_id(
                    <Download as ql_rpc::request_with_progress::RequestWithProgress>::ROUTE
                )
            );
            assert_eq!(request, b"logo".to_vec());

            let mut encoded = Vec::new();
            ql_rpc::request_with_progress::encode_progress::<Download>(
                &b"10".to_vec(),
                &mut encoded,
            );
            ql_rpc::request_with_progress::encode_progress::<Download>(
                &b"90".to_vec(),
                &mut encoded,
            );
            ql_rpc::request_with_progress::encode_response::<Download>(
                &b"done".to_vec(),
                &mut encoded,
            );

            let mut writer = inbound.writer;
            writer.write(Bytes::from(encoded)).await.unwrap();
            writer.finish().await.unwrap();
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let mut download = rpc
            .request_with_progress::<Download>(&b"logo".to_vec())
            .await
            .unwrap();

        assert_eq!(download.progress().await, Some(b"10".to_vec()));
        assert_eq!(download.progress().await, Some(b"90".to_vec()));
        assert_eq!(download.progress().await, None);
        assert_eq!(download.await.unwrap(), b"done".to_vec());

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_router_handles_download() {
    #[derive(Clone)]
    struct RouterState {
        seen: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl crate::rpc::DownloadHandler<BlobDownload, QlStream> for RouterState {
        fn handle(
            self,
            request: Vec<u8>,
            responder: DownloadResponder<Vec<u8>, StreamWriter>,
        ) {
            let seen = self.seen.clone();
            tokio::task::spawn_local(async move {
                seen.borrow_mut().push(request);
                let mut writer: DownloadWriter<StreamWriter> =
                    responder.respond(b"image/png".to_vec()).await.unwrap();
                writer.send(Bytes::from_static(b"abc")).await.unwrap();
                writer.send(Bytes::from_static(b"def")).await.unwrap();
                writer.finish().await.unwrap();
            });
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let seen = Rc::new(RefCell::new(Vec::new()));

        let router =
            ql_rpc::Router::<_, QlStream, crate::rpc::LocalSpawn>::builder(crate::rpc::LocalSpawn)
                .download::<BlobDownload>()
                .build(RouterState { seen: seen.clone() });

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(inbound) {
                fut.await;
            }
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let download = rpc.download::<BlobDownload>(&b"logo".to_vec()).await.unwrap();
        let (header, mut reader) = download.into_reader().await.unwrap();
        assert_eq!(header, b"image/png".to_vec());
        assert_eq!(reader.read_chunk().await.unwrap(), Some(Bytes::from_static(b"abc")));
        assert_eq!(reader.read_chunk().await.unwrap(), Some(Bytes::from_static(b"def")));
        assert_eq!(reader.read_chunk().await.unwrap(), None);
        assert_eq!(seen.borrow().as_slice(), &[b"logo".to_vec()]);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

async fn read_rpc_value<T>(mut reader: crate::StreamReader) -> T
where
    T: ql_rpc::RpcCodec,
    T::Error: std::fmt::Debug,
{
    let mut value_reader = ql_rpc::ValueReader::<T>::default();

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
