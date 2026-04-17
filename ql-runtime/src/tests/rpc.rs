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
    DownloadHandler, DownloadResponder, DownloadWriter, LocalSpawn, NotificationHandler,
    ProgressHandler, ProgressResponder, RequestHandler, Response, RouteId, SendSpawn,
    StreamCloseCode, SubscriptionHandler, SubscriptionResponder, UploadHandler, UploadReader,
    UploadResponder,
};

use super::*;
use crate::{rpc::RpcError, QlStream, StreamWriter};

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

struct Notice;

impl ql_rpc::notification::Notification for Notice {
    const ROUTE: RouteId = RouteId::from_u32(521);
    type Error = core::convert::Infallible;
    type Payload = Vec<u8>;
}

struct Download;

impl ql_rpc::progress::Progress for Download {
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

struct BlobUpload;

impl ql_rpc::upload::Upload for BlobUpload {
    const ROUTE: RouteId = RouteId::from_u32(55);
    type Error = core::convert::Infallible;
    type Request = Vec<u8>;
    type Response = Vec<u8>;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_request() {
    #[derive(Clone)]
    struct RouterState {
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl RequestHandler<Echo, QlStream> for RouterState {
        fn handle(self, request: String, response: Response<String, StreamWriter>) {
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

        let router = ql_rpc::Router::<_, QlStream, SendSpawn>::builder(SendSpawn)
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

fn assert_send<T: Send>(value: T) -> T {
    value
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_notification() {
    #[derive(Clone)]
    struct RouterState {
        seen: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl NotificationHandler<Notice, QlStream> for RouterState {
        fn handle(self, payload: Vec<u8>) {
            self.seen.borrow_mut().push(payload);
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let seen = Rc::new(RefCell::new(Vec::new()));

        let router = ql_rpc::Router::<_, QlStream, LocalSpawn>::builder(LocalSpawn)
            .notification::<Notice>()
            .build(RouterState { seen: seen.clone() });

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(inbound) {
                fut.await;
            }
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        rpc.notification::<Notice>(&b"hello".to_vec())
            .await
            .unwrap();
        assert_eq!(seen.borrow().as_slice(), &[b"hello".to_vec()]);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_subscrption() {
    #[derive(Clone)]
    struct RouterState {
        seen: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl SubscriptionHandler<Feed, QlStream> for RouterState {
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
        let router = ql_rpc::Router::<_, QlStream, LocalSpawn>::builder(LocalSpawn)
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
async fn rpc_router_enforces_max_request_bytes() {
    #[derive(Clone)]
    struct LimitedState;

    impl RequestHandler<Echo, QlStream> for LimitedState {
        fn handle(self, request: String, response: Response<String, StreamWriter>) {
            tokio::task::spawn_local(async move {
                let _ = response.respond(request).await;
            });
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let router = ql_rpc::Router::<_, QlStream, LocalSpawn>::builder(LocalSpawn)
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
            Err(RpcError::Closed(code)) if code == StreamCloseCode::LIMIT
        ));

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_progress() {
    #[derive(Clone)]
    struct RouterState {
        seen: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl ProgressHandler<Download, QlStream> for RouterState {
        fn handle(
            self,
            request: Vec<u8>,
            mut responder: ProgressResponder<Download, StreamWriter>,
        ) {
            let seen = self.seen.clone();
            tokio::task::spawn_local(async move {
                seen.borrow_mut().push(request);
                responder.send(b"10".to_vec()).await.unwrap();
                responder.send(b"90".to_vec()).await.unwrap();
                responder.finish(b"done".to_vec()).await.unwrap();
            });
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let seen = Rc::new(RefCell::new(Vec::new()));

        let router = ql_rpc::Router::<_, QlStream, LocalSpawn>::builder(LocalSpawn)
            .progress::<Download>()
            .build(RouterState { seen: seen.clone() });

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(inbound) {
                fut.await;
            }
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let mut download = rpc.progress::<Download>(&b"logo".to_vec()).await.unwrap();

        assert_eq!(download.next().await, Some(b"10".to_vec()));
        assert_eq!(download.next().await, Some(b"90".to_vec()));
        assert_eq!(download.next().await, None);
        assert_eq!(download.await.unwrap(), b"done".to_vec());
        assert_eq!(seen.borrow().as_slice(), &[b"logo".to_vec()]);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_download() {
    #[derive(Clone)]
    struct RouterState {
        seen: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl DownloadHandler<BlobDownload, QlStream> for RouterState {
        fn handle(self, request: Vec<u8>, responder: DownloadResponder<Vec<u8>, StreamWriter>) {
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

        let router = ql_rpc::Router::<_, QlStream, LocalSpawn>::builder(LocalSpawn)
            .download::<BlobDownload>()
            .build(RouterState { seen: seen.clone() });

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(inbound) {
                fut.await;
            }
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let download = rpc
            .download::<BlobDownload>(&b"logo".to_vec())
            .await
            .unwrap();
        let (header, mut reader) = download.into_reader().await.unwrap();
        assert_eq!(header, b"image/png".to_vec());
        assert_eq!(
            reader.read_chunk().await.unwrap(),
            Some(Bytes::from_static(b"abc"))
        );
        assert_eq!(
            reader.read_chunk().await.unwrap(),
            Some(Bytes::from_static(b"def"))
        );
        assert_eq!(reader.read_chunk().await.unwrap(), None);
        assert_eq!(seen.borrow().as_slice(), &[b"logo".to_vec()]);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_upload() {
    #[derive(Clone)]
    struct RouterState {
        requests: Rc<RefCell<Vec<Vec<u8>>>>,
        uploads: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl UploadHandler<BlobUpload, QlStream> for RouterState {
        fn handle(
            self,
            request: Vec<u8>,
            mut upload: UploadReader<crate::StreamReader>,
            responder: UploadResponder<Vec<u8>, StreamWriter>,
        ) {
            let requests = self.requests.clone();
            let uploads = self.uploads.clone();
            tokio::task::spawn_local(async move {
                requests.borrow_mut().push(request);

                let mut body = Vec::new();
                while let Some(chunk) = upload.read_chunk().await.unwrap() {
                    body.extend_from_slice(&chunk);
                }
                uploads.borrow_mut().push(body.clone());

                responder.respond(body).await.unwrap();
            });
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let requests = Rc::new(RefCell::new(Vec::new()));
        let uploads = Rc::new(RefCell::new(Vec::new()));

        let router = ql_rpc::Router::<_, QlStream, LocalSpawn>::builder(LocalSpawn)
            .upload::<BlobUpload>()
            .build(RouterState {
                requests: requests.clone(),
                uploads: uploads.clone(),
            });

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(inbound) {
                fut.await;
            }
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let mut upload = rpc.upload::<BlobUpload>(&b"logo".to_vec()).await.unwrap();
        upload.send(Bytes::from_static(b"abc")).await.unwrap();
        upload.send(Bytes::from_static(b"def")).await.unwrap();
        let response = upload.finish().await.unwrap();

        assert_eq!(response, b"abcdef".to_vec());
        assert_eq!(requests.borrow().as_slice(), &[b"logo".to_vec()]);
        assert_eq!(uploads.borrow().as_slice(), &[b"abcdef".to_vec()]);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}
