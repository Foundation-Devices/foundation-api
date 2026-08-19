use std::{
    cell::RefCell,
    future::Future,
    rc::Rc,
    str::Utf8Error,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::BufMut;
use ql_codec::Encode;
use ql_rpc::{
    progress::{ProgressHandlerLocal, ProgressResponder},
    request::{RequestHandler, Response},
    Context, LocalSpawner, SendSpawner, Spawner,
};

use super::*;
use crate::{QlStream, StreamWriter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TestRouteKey(u64);

impl ql_rpc::RpcRouteKey for TestRouteKey {
    fn encoded_len(&self) -> usize {
        ql_codec::Varint(self.0).encoded_len()
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        ql_codec::Varint(self.0).encode(out);
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut reader = ql_codec::Reader::new(bytes);
        let route_id = reader.decode::<ql_codec::Varint<u64>>().ok()?;
        Some(Self(*route_id))
    }
}

macro_rules! test_route {
    ($route:ty, $id:expr) => {
        impl ql_rpc::Route for $route {
            type Key = TestRouteKey;

            fn key() -> Self::Key {
                TestRouteKey($id)
            }
        }
    };
}

#[derive(Debug, Clone, Copy)]
struct TokioLocalSpawner;

impl Spawner for TokioLocalSpawner {
    type Handle = tokio::task::JoinHandle<()>;
}

impl LocalSpawner for TokioLocalSpawner {
    fn spawn<F>(&self, fut: F) -> Self::Handle
    where
        F: Future<Output = ()> + 'static,
    {
        tokio::task::spawn_local(fut)
    }
}

#[derive(Debug, Clone, Copy)]
struct TokioSendSpawner;

impl Spawner for TokioSendSpawner {
    type Handle = tokio::task::JoinHandle<()>;
}

impl SendSpawner for TokioSendSpawner {
    fn spawn<F>(&self, fut: F) -> Self::Handle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        tokio::task::spawn(fut)
    }
}

struct Echo;

test_route!(Echo, 51);

impl ql_rpc::request::Request for Echo {
    type Error = Utf8Error;
    type Request = String;
    type Response = String;
}

struct Download;

test_route!(Download, 52);

impl ql_rpc::progress::Progress for Download {
    type Error = core::convert::Infallible;
    type Request = Vec<u8>;
    type Progress = Vec<u8>;
    type Response = Vec<u8>;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_request_uses_runtime_streams() {
    #[derive(Clone)]
    struct RouterState {
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl RequestHandler<Echo, QlStream> for RouterState {
        async fn handle(
            self,
            _context: Context,
            request: String,
            response: Response<String, StreamWriter>,
        ) {
            self.seen.lock().unwrap().push(request);
            response.respond("world".into()).await.unwrap();
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let seen = Arc::new(Mutex::new(Vec::new()));

        let router = ql_rpc::Router::<TestRouteKey, _, QlStream, TokioSendSpawner>::builder_send(
            TokioSendSpawner,
        )
        .request::<Echo>()
        .build(RouterState { seen: seen.clone() });

        let responder = tokio::task::spawn_local(async move {
            let (info, stream) = inbound_b.recv().await.unwrap();
            if let Some(fut) = router.handle(info, stream) {
                let fut = assert_send(fut);
                fut.await.unwrap();
            }
        });

        let response = pair
            .side_mut(Side::A)
            .handle
            .rpc()
            .request::<Echo>(&"hello".into(), StreamOptions::default())
            .await
            .unwrap();
        assert_eq!(response, "world");
        assert_eq!(&*seen.lock().unwrap(), &["hello".to_string()]);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

fn assert_send<T: Send>(value: T) -> T {
    value
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_progress_preserves_response_reader_after_request_finish() {
    #[derive(Clone)]
    struct RouterState {
        seen: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl ProgressHandlerLocal<Download, QlStream> for RouterState {
        async fn handle(
            self,
            _context: Context,
            request: Vec<u8>,
            mut responder: ProgressResponder<Download, StreamWriter>,
        ) {
            self.seen.borrow_mut().push(request);
            responder.send(b"10".to_vec()).await.unwrap();
            responder.send(b"90".to_vec()).await.unwrap();
            responder.finish(b"done".to_vec()).await.unwrap();
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let seen = Rc::new(RefCell::new(Vec::new()));

        let router = ql_rpc::Router::<TestRouteKey, _, QlStream, TokioLocalSpawner>::builder_local(
            TokioLocalSpawner,
        )
        .progress::<Download>()
        .build(RouterState { seen: seen.clone() });

        let responder = tokio::task::spawn_local(async move {
            let (info, stream) = inbound_b.recv().await.unwrap();
            if let Some(fut) = router.handle(info, stream) {
                fut.await.unwrap();
            }
        });

        let mut download = pair
            .side_mut(Side::A)
            .handle
            .rpc()
            .progress::<Download>(&b"logo".to_vec(), StreamOptions::default())
            .await
            .unwrap();
        assert_eq!(download.next_progress().await, Some(b"10".to_vec()));
        assert_eq!(download.next_progress().await, Some(b"90".to_vec()));
        assert_eq!(download.next_progress().await, None);
        assert_eq!(download.await.unwrap(), b"done".to_vec());
        assert_eq!(seen.borrow().as_slice(), &[b"logo".to_vec()]);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}
