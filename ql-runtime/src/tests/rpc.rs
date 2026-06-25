use std::{
    cell::RefCell,
    future::Future,
    rc::Rc,
    str::Utf8Error,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use ql_rpc::{
    Context, DownloadHandlerLocal, DownloadStart, DuplexHandlerLocal, DuplexPeer, LocalSpawner,
    NotificationHandlerLocal, ProgressHandlerLocal, ProgressResponder, RequestHandler,
    RequestHandlerLocal, ResetCode, ResetOrigin, Response, RouteId, SendSpawner, ServiceId,
    Spawner, SubscriptionHandlerLocal, SubscriptionResponder, UploadHandlerLocal, UploadReader,
    UploadResponder,
};

use super::*;
use crate::{QlStream, QlStreamError, StreamWriter};

const TEST_SERVICE: ServiceId = ServiceId([7; 16]);

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

impl ql_rpc::Route for Echo {
    const SERVICE: ServiceId = TEST_SERVICE;
    const ROUTE: RouteId = RouteId::from_u32(51);
}

impl ql_rpc::request::Request for Echo {
    type Error = Utf8Error;

    type Request = String;
    type Response = String;
}

struct Feed;

impl ql_rpc::Route for Feed {
    const SERVICE: ServiceId = TEST_SERVICE;
    const ROUTE: RouteId = RouteId::from_u32(52);
}

impl ql_rpc::subscription::Subscription for Feed {
    type Error = core::convert::Infallible;
    type Request = Vec<u8>;
    type Event = Vec<u8>;
}

struct Notice;

impl ql_rpc::Route for Notice {
    const SERVICE: ServiceId = TEST_SERVICE;
    const ROUTE: RouteId = RouteId::from_u32(521);
}

impl ql_rpc::notification::Notification for Notice {
    type Error = core::convert::Infallible;
    type Payload = Vec<u8>;
}

struct Download;

impl ql_rpc::Route for Download {
    const SERVICE: ServiceId = TEST_SERVICE;
    const ROUTE: RouteId = RouteId::from_u32(53);
}

impl ql_rpc::progress::Progress for Download {
    type Error = core::convert::Infallible;
    type Request = Vec<u8>;
    type Progress = Vec<u8>;
    type Response = Vec<u8>;
}

struct BlobDownload;

impl ql_rpc::Route for BlobDownload {
    const SERVICE: ServiceId = TEST_SERVICE;
    const ROUTE: RouteId = RouteId::from_u32(54);
}

impl ql_rpc::download::Download for BlobDownload {
    type Error = core::convert::Infallible;
    type Request = Vec<u8>;
    type ResponseHeader = Vec<u8>;
    type PartHeader = Vec<u8>;
}

struct BlobUpload;

impl ql_rpc::Route for BlobUpload {
    const SERVICE: ServiceId = TEST_SERVICE;
    const ROUTE: RouteId = RouteId::from_u32(55);
}

impl ql_rpc::upload::Upload for BlobUpload {
    type Error = core::convert::Infallible;
    type Request = Vec<u8>;
    type PartHeader = Vec<u8>;
    type Response = Vec<u8>;
}

struct Chat;

impl ql_rpc::Route for Chat {
    const SERVICE: ServiceId = TEST_SERVICE;
    const ROUTE: RouteId = RouteId::from_u32(56);
}

impl ql_rpc::duplex::Duplex for Chat {
    type Error = core::convert::Infallible;
    type InitiatorEvent = Vec<u8>;
    type ResponderEvent = Vec<u8>;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_request() {
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
            let seen = self.seen.clone();
            seen.lock().unwrap().push(request);
            let _ = response.respond("world".into()).await;
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let seen = Arc::new(Mutex::new(Vec::new()));

        let router =
            ql_rpc::Router::<_, QlStream, TokioSendSpawner>::builder_send(TokioSendSpawner)
                .request::<Echo>()
                .build(RouterState { seen: seen.clone() });

        let responder = tokio::task::spawn_local(async move {
            let (info, stream) = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(info, stream) {
                let fut = assert_send(fut);
                fut.await.unwrap();
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

    impl NotificationHandlerLocal<Notice, QlStream> for RouterState {
        async fn handle(self, _context: Context, payload: Vec<u8>) {
            self.seen.borrow_mut().push(payload);
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let seen = Rc::new(RefCell::new(Vec::new()));

        let router =
            ql_rpc::Router::<_, QlStream, TokioLocalSpawner>::builder_local(TokioLocalSpawner)
                .notification::<Notice>()
                .build(RouterState { seen: seen.clone() });

        let responder = tokio::task::spawn_local(async move {
            let (info, stream) = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(info, stream) {
                fut.await.unwrap();
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

    impl SubscriptionHandlerLocal<Feed, QlStream> for RouterState {
        async fn handle(
            self,
            _context: Context,
            request: Vec<u8>,
            mut response: SubscriptionResponder<Vec<u8>, StreamWriter>,
        ) {
            let seen = self.seen.clone();
            seen.borrow_mut().push(request);
            let _ = response.send(b"one".to_vec()).await;
            let _ = response.send(b"two".to_vec()).await;
            let _ = response.finish().await;
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);

        let seen = Rc::new(RefCell::new(Vec::new()));
        let router =
            ql_rpc::Router::<_, QlStream, TokioLocalSpawner>::builder_local(TokioLocalSpawner)
                .subscription::<Feed>()
                .build(RouterState { seen: seen.clone() });

        let responder = tokio::task::spawn_local(async move {
            let (info, stream) = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(info, stream) {
                fut.await.unwrap();
            }
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let mut subscription = rpc.subscribe::<Feed>(&b"watch".to_vec()).await.unwrap();
        assert_eq!(
            subscription.next_event().await.unwrap().unwrap(),
            b"one".to_vec()
        );
        assert_eq!(
            subscription.next_event().await.unwrap().unwrap(),
            b"two".to_vec()
        );
        assert!(subscription.next_event().await.is_none());
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

    impl RequestHandlerLocal<Echo, QlStream> for LimitedState {
        async fn handle(
            self,
            _context: Context,
            request: String,
            response: Response<String, StreamWriter>,
        ) {
            let _ = response.respond(request).await;
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let router =
            ql_rpc::Router::<_, QlStream, TokioLocalSpawner>::builder_local(TokioLocalSpawner)
                .max_request_bytes(4)
                .request::<Echo>()
                .build(LimitedState);

        let responder = tokio::task::spawn_local(async move {
            let (info, stream) = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(info, stream) {
                fut.await.unwrap();
            }
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let response = rpc.request::<Echo>(&"hello".to_string()).await;
        assert!(matches!(
            response,
            Err(ql_rpc::RpcError::Transport(QlStreamError::StreamReset { code, origin }))
                if code == ResetCode::LIMIT && origin == ResetOrigin::Peer
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

    impl ProgressHandlerLocal<Download, QlStream> for RouterState {
        async fn handle(
            self,
            _context: Context,
            request: Vec<u8>,
            mut responder: ProgressResponder<Download, StreamWriter>,
        ) {
            let seen = self.seen.clone();
            seen.borrow_mut().push(request);
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

        let router =
            ql_rpc::Router::<_, QlStream, TokioLocalSpawner>::builder_local(TokioLocalSpawner)
                .progress::<Download>()
                .build(RouterState { seen: seen.clone() });

        let responder = tokio::task::spawn_local(async move {
            let (info, stream) = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(info, stream) {
                fut.await.unwrap();
            }
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let mut download = rpc.progress::<Download>(&b"logo".to_vec()).await.unwrap();

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

#[tokio::test(flavor = "current_thread")]
async fn rpc_download() {
    #[derive(Clone)]
    struct RouterState {
        seen: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl DownloadHandlerLocal<BlobDownload, QlStream> for RouterState {
        async fn handle(
            self,
            _context: Context,
            request: Vec<u8>,
            download: DownloadStart<BlobDownload, StreamWriter>,
        ) {
            let seen = self.seen.clone();
            seen.borrow_mut().push(request);
            let mut writer = download.start(b"image/png".to_vec()).await.unwrap();
            let mut part = writer.start_part(b"icon".to_vec()).await.unwrap();
            part.send(Bytes::from_static(b"abc")).await.unwrap();
            part.send(Bytes::from_static(b"def")).await.unwrap();
            part.finish().await.unwrap();
            let mut part = writer.start_part(b"manifest".to_vec()).await.unwrap();
            part.send(Bytes::from_static(b"{}")).await.unwrap();
            part.finish().await.unwrap();
            writer.finish().await.unwrap();
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let seen = Rc::new(RefCell::new(Vec::new()));

        let router =
            ql_rpc::Router::<_, QlStream, TokioLocalSpawner>::builder_local(TokioLocalSpawner)
                .download::<BlobDownload>()
                .build(RouterState { seen: seen.clone() });

        let responder = tokio::task::spawn_local(async move {
            let (info, stream) = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(info, stream) {
                fut.await.unwrap();
            }
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let download = rpc
            .download::<BlobDownload>(&b"logo".to_vec())
            .await
            .unwrap();
        let (header, mut reader) = download.start().await.unwrap();
        assert_eq!(header, b"image/png".to_vec());
        {
            let (part_header, mut part) = reader.next_part().await.unwrap().unwrap();
            assert_eq!(part_header, b"icon".to_vec());
            assert_eq!(
                part.read_chunk().await.unwrap(),
                Some(Bytes::from_static(b"abc"))
            );
            assert_eq!(
                part.read_chunk().await.unwrap(),
                Some(Bytes::from_static(b"def"))
            );
            assert_eq!(part.read_chunk().await.unwrap(), None);
        }
        {
            let (part_header, mut part) = reader.next_part().await.unwrap().unwrap();
            assert_eq!(part_header, b"manifest".to_vec());
            assert_eq!(
                part.read_chunk().await.unwrap(),
                Some(Bytes::from_static(b"{}"))
            );
            assert_eq!(part.read_chunk().await.unwrap(), None);
        }
        assert!(reader.next_part().await.unwrap().is_none());
        assert_eq!(seen.borrow().as_slice(), &[b"logo".to_vec()]);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_download_complete() {
    #[derive(Clone)]
    struct RouterState {
        seen: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl DownloadHandlerLocal<BlobDownload, QlStream> for RouterState {
        async fn handle(
            self,
            _context: Context,
            request: Vec<u8>,
            download: DownloadStart<BlobDownload, StreamWriter>,
        ) {
            self.seen.borrow_mut().push(request);
            download.complete(b"not found".to_vec()).await.unwrap();
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let seen = Rc::new(RefCell::new(Vec::new()));

        let router =
            ql_rpc::Router::<_, QlStream, TokioLocalSpawner>::builder_local(TokioLocalSpawner)
                .download::<BlobDownload>()
                .build(RouterState { seen: seen.clone() });

        let responder = tokio::task::spawn_local(async move {
            let (info, stream) = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(info, stream) {
                fut.await.unwrap();
            }
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let download = rpc
            .download::<BlobDownload>(&b"logo".to_vec())
            .await
            .unwrap();
        let (header, reader) = download.start().await.unwrap();
        assert_eq!(header, b"not found".to_vec());
        reader.complete().await.unwrap();
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

    impl UploadHandlerLocal<BlobUpload, QlStream> for RouterState {
        async fn handle(
            self,
            _context: Context,
            request: Vec<u8>,
            mut upload: UploadReader<BlobUpload, crate::StreamReader>,
            responder: UploadResponder<Vec<u8>, StreamWriter>,
        ) {
            let requests = self.requests.clone();
            let uploads = self.uploads.clone();
            requests.borrow_mut().push(request);

            let mut body = Vec::new();
            while let Some((part_header, mut part)) = upload.next_part().await.unwrap() {
                body.extend_from_slice(&part_header);
                body.push(b':');
                while let Some(chunk) = part.read_chunk().await.unwrap() {
                    body.extend_from_slice(&chunk);
                }
                body.push(b';');
            }
            uploads.borrow_mut().push(body.clone());

            responder.respond(body).await.unwrap();
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let requests = Rc::new(RefCell::new(Vec::new()));
        let uploads = Rc::new(RefCell::new(Vec::new()));

        let router =
            ql_rpc::Router::<_, QlStream, TokioLocalSpawner>::builder_local(TokioLocalSpawner)
                .upload::<BlobUpload>()
                .build(RouterState {
                    requests: requests.clone(),
                    uploads: uploads.clone(),
                });

        let responder = tokio::task::spawn_local(async move {
            let (info, stream) = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(info, stream) {
                fut.await.unwrap();
            }
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let mut upload = rpc.upload::<BlobUpload>(&b"logo".to_vec()).await.unwrap();
        let mut part = upload.start_part(b"icon".to_vec()).await.unwrap();
        part.send(Bytes::from_static(b"abc")).await.unwrap();
        part.send(Bytes::from_static(b"def")).await.unwrap();
        part.finish().await.unwrap();
        let mut part = upload.start_part(b"manifest".to_vec()).await.unwrap();
        part.send(Bytes::from_static(b"{}")).await.unwrap();
        part.finish().await.unwrap();
        let response = upload.finish().await.unwrap();

        assert_eq!(response, b"icon:abcdef;manifest:{};".to_vec());
        assert_eq!(requests.borrow().as_slice(), &[b"logo".to_vec()]);
        assert_eq!(
            uploads.borrow().as_slice(),
            &[b"icon:abcdef;manifest:{};".to_vec()]
        );

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_duplex() {
    #[derive(Clone)]
    struct RouterState {
        seen: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl DuplexHandlerLocal<Chat, QlStream> for RouterState {
        async fn handle(
            self,
            _context: Context,
            mut peer: DuplexPeer<Chat, StreamWriter, crate::StreamReader>,
        ) {
            let seen = self.seen.clone();
            let first = peer.receiver.next_event().await.unwrap().unwrap();
            seen.borrow_mut().push(first);

            peer.sender
                .send(&b"challenge-response".to_vec())
                .await
                .unwrap();

            let second = peer.receiver.next_event().await.unwrap().unwrap();
            seen.borrow_mut().push(second);

            peer.sender.finish();
        }
    }

    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let seen = Rc::new(RefCell::new(Vec::new()));

        let router =
            ql_rpc::Router::<_, QlStream, TokioLocalSpawner>::builder_local(TokioLocalSpawner)
                .duplex::<Chat>()
                .build(RouterState { seen: seen.clone() });

        let responder = tokio::task::spawn_local(async move {
            let (info, stream) = inbound_b.recv().await.unwrap();
            if let Some((_, fut)) = router.handle(info, stream) {
                fut.await.unwrap();
            }
        });

        let rpc = pair.side_mut(Side::A).handle.rpc();
        let mut chat = rpc.duplex::<Chat>().await.unwrap();
        chat.sender.send(&b"challenge".to_vec()).await.unwrap();
        assert_eq!(
            chat.receiver.next_event().await.unwrap().unwrap(),
            b"challenge-response".to_vec()
        );
        chat.sender.send(&b"verification".to_vec()).await.unwrap();
        chat.sender.finish();
        assert!(chat.receiver.next_event().await.is_none());

        assert_eq!(
            seen.borrow().as_slice(),
            &[b"challenge".to_vec(), b"verification".to_vec()]
        );

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}
