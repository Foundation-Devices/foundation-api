use std::{
    cell::RefCell,
    collections::VecDeque,
    convert::Infallible,
    future::{ready, Future, Ready},
    rc::Rc,
    task::{Context as TaskContext, Poll, Waker},
};

use bytes::{BufMut, Bytes};
use ql_common::{ResetCode, StreamId, QID};

use super::{download, duplex, notification, progress, request, subscription, upload};
use crate::{Context, Route, RouterConfig, RpcRead, RpcRouteKey, RpcStream, RpcWrite};

const CONTEXT: Context = Context {
    qid: QID([0; QID::SIZE]),
    stream_id: StreamId(0),
};

struct TestStream {
    reader: TestReader,
    writer: TestWriter,
}

struct TestReader {
    pipe: Rc<RefCell<PipeState>>,
    active: bool,
}

struct TestWriter {
    pipe: Rc<RefCell<PipeState>>,
    chunk_size: usize,
    pending_write: bool,
    open: bool,
    terminal: Option<ResetError>,
}

#[derive(Default)]
struct PipeState {
    chunks: VecDeque<Bytes>,
    finished: bool,
    reset: Option<ResetCode>,
    reader: Option<Waker>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResetError(ResetCode);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TestKey(u8);

impl RpcStream for TestStream {
    type Error = ResetError;
    type Reader = TestReader;
    type Writer = TestWriter;

    fn split(self) -> (Self::Reader, Self::Writer) {
        (self.reader, self.writer)
    }
}

impl RpcRead for TestReader {
    type Error = ResetError;

    fn poll_read(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<Bytes, Self::Error>> {
        if !self.active {
            return Poll::Ready(Ok(Bytes::new()));
        }

        let mut pipe = self.pipe.borrow_mut();
        if let Some(code) = pipe.reset {
            self.active = false;
            return Poll::Ready(Err(ResetError(code)));
        }
        if let Some(chunk) = pipe.chunks.pop_front() {
            return Poll::Ready(Ok(chunk));
        }
        if pipe.finished {
            self.active = false;
            return Poll::Ready(Ok(Bytes::new()));
        }
        pipe.reader = Some(cx.waker().clone());
        Poll::Pending
    }

    fn reset(&mut self, code: ResetCode) {
        if !self.active {
            return;
        }
        self.active = false;
        let mut pipe = self.pipe.borrow_mut();
        if pipe.reset.is_none() {
            pipe.reset = Some(code);
            pipe.chunks.clear();
            pipe.wake_reader();
        }
    }
}

impl Drop for TestReader {
    fn drop(&mut self) {
        self.reset(ResetCode::DROPPED);
    }
}

impl TestWriter {
    fn observe_reset(&mut self) -> Option<ResetError> {
        if let Some(error) = self.terminal {
            return Some(error);
        }
        let code = self.pipe.borrow().reset?;
        let error = ResetError(code);
        self.open = false;
        self.terminal = Some(error);
        Some(error)
    }
}

impl RpcWrite for TestWriter {
    type Error = ResetError;
    type Finish = Ready<Result<(), Self::Error>>;

    fn poll_write(
        &mut self,
        bytes: &mut Bytes,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if let Some(error) = self.observe_reset() {
            return Poll::Ready(Err(error));
        }
        if self.pending_write {
            self.pending_write = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        self.pending_write = true;
        let mut pipe = self.pipe.borrow_mut();
        while !bytes.is_empty() {
            let len = bytes.len().min(self.chunk_size);
            pipe.chunks.push_back(bytes.split_to(len));
        }
        pipe.wake_reader();
        Poll::Ready(Ok(()))
    }

    fn finish(mut self) -> Self::Finish {
        if let Some(error) = self.observe_reset() {
            return ready(Err(error));
        }
        self.open = false;
        let mut pipe = self.pipe.borrow_mut();
        pipe.finished = true;
        pipe.wake_reader();
        ready(Ok(()))
    }

    fn reset(&mut self, code: ResetCode) {
        if !self.open {
            return;
        }
        self.open = false;
        self.terminal = Some(ResetError(code));
        let mut pipe = self.pipe.borrow_mut();
        if pipe.reset.is_none() {
            pipe.reset = Some(code);
            pipe.chunks.clear();
            pipe.wake_reader();
        }
    }
}

impl Drop for TestWriter {
    fn drop(&mut self) {
        self.reset(ResetCode::DROPPED);
    }
}

impl PipeState {
    fn wake_reader(&mut self) {
        if let Some(waker) = self.reader.take() {
            waker.wake();
        }
    }
}

impl RpcRouteKey for TestKey {
    fn encoded_len(&self) -> usize {
        1
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        out.put_u8(self.0);
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let [key] = bytes else {
            return None;
        };
        Some(Self(*key))
    }
}

fn stream_pair(chunk_size: usize) -> (TestStream, TestStream) {
    let left_to_right = Rc::new(RefCell::new(PipeState::default()));
    let right_to_left = Rc::new(RefCell::new(PipeState::default()));
    (
        TestStream {
            reader: TestReader {
                pipe: right_to_left.clone(),
                active: true,
            },
            writer: TestWriter {
                pipe: left_to_right.clone(),
                chunk_size,
                pending_write: true,
                open: true,
                terminal: None,
            },
        },
        TestStream {
            reader: TestReader {
                pipe: left_to_right,
                active: true,
            },
            writer: TestWriter {
                pipe: right_to_left,
                chunk_size,
                pending_write: true,
                open: true,
                terminal: None,
            },
        },
    )
}

fn chunk_sizes() -> impl Iterator<Item = usize> {
    (1..=16).chain(std::iter::once(usize::MAX))
}

fn run<A, B>(left: A, right: B) -> (A::Output, B::Output)
where
    A: Future,
    B: Future,
{
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let mut left_output = None;
    let mut right_output = None;
    let mut cx = TaskContext::from_waker(Waker::noop());

    for _ in 0..10_000 {
        if left_output.is_none() {
            if let Poll::Ready(output) = left.as_mut().poll(&mut cx) {
                left_output = Some(output);
            }
        }
        if right_output.is_none() {
            if let Poll::Ready(output) = right.as_mut().poll(&mut cx) {
                right_output = Some(output);
            }
        }
        if left_output.is_some() && right_output.is_some() {
            return (left_output.take().unwrap(), right_output.take().unwrap());
        }
    }
    panic!("rpc test did not complete");
}

macro_rules! route {
    ($rpc:ty, $key:expr) => {
        impl Route for $rpc {
            type Key = TestKey;

            fn key() -> Self::Key {
                TestKey($key)
            }
        }
    };
}

#[test]
fn request() {
    struct Rpc;
    route!(Rpc, 1);

    impl request::Request for Rpc {
        type Error = Infallible;
        type Request = Vec<u8>;
        type Response = Vec<u8>;
    }

    for chunk_size in chunk_sizes() {
        let (client, server) = stream_pair(chunk_size);
        let message = b"hello".to_vec();
        let client = request::call::<Rpc, _>(client, &message);
        let server = request::handle_request::<(), Vec<u8>, Vec<u8>, Infallible, _, _, _, _>(
            (),
            CONTEXT,
            RouterConfig::default(),
            server,
            |(), _, request, responder| async move {
                assert_eq!(request, b"hello".to_vec());
                responder.respond(b"world".to_vec()).await.unwrap();
            },
            |_, error| panic!("request failed: {error:?}"),
        );
        let (response, ()) = run(client, server);
        assert_eq!(response.unwrap(), b"world".to_vec());
    }
}

#[test]
fn notification() {
    struct Rpc;
    route!(Rpc, 2);

    impl notification::Notification for Rpc {
        type Error = Infallible;
        type Payload = Vec<u8>;
    }

    for chunk_size in chunk_sizes() {
        let (client, server) = stream_pair(chunk_size);
        let message = b"hello".to_vec();
        let client = notification::send::<Rpc, _>(client, &message);
        let server = notification::handle_notification::<(), Vec<u8>, Infallible, _, _, _, _>(
            (),
            CONTEXT,
            RouterConfig::default(),
            server,
            |(), _, payload| async move {
                assert_eq!(payload, b"hello".to_vec());
            },
            |_, error| panic!("notification failed: {error:?}"),
        );
        let (result, ()) = run(client, server);
        result.unwrap();
    }
}

#[test]
fn subscription() {
    struct Rpc;
    route!(Rpc, 3);

    impl subscription::Subscription for Rpc {
        type Error = Infallible;
        type Request = Vec<u8>;
        type Event = Vec<u8>;
    }

    for chunk_size in chunk_sizes() {
        let (client, server) = stream_pair(chunk_size);
        let client = async move {
            let mut subscription = subscription::start::<Rpc, _>(client, &b"watch".to_vec())
                .await
                .unwrap();
            assert_eq!(
                subscription.next_event().await.unwrap().unwrap(),
                b"one".to_vec()
            );
            assert_eq!(
                subscription.next_event().await.unwrap().unwrap(),
                b"two".to_vec()
            );
            assert!(subscription.next_event().await.is_none());
        };
        let server =
            subscription::handle_subscription::<(), Vec<u8>, Vec<u8>, Infallible, _, _, _, _>(
                (),
                CONTEXT,
                RouterConfig::default(),
                server,
                |(), _, request, mut responder| async move {
                    assert_eq!(request, b"watch".to_vec());
                    responder.send(&b"one".to_vec()).await.unwrap();
                    responder.send(&b"two".to_vec()).await.unwrap();
                    responder.finish().await.unwrap();
                },
                |_, error| panic!("subscription failed: {error:?}"),
            );
        run(client, server);
    }
}

#[test]
fn progress() {
    struct Rpc;
    route!(Rpc, 4);

    impl progress::Progress for Rpc {
        type Error = Infallible;
        type Request = Vec<u8>;
        type Progress = Vec<u8>;
        type Response = Vec<u8>;
    }

    for chunk_size in chunk_sizes() {
        let (client, server) = stream_pair(chunk_size);
        let client = async move {
            let mut progress = progress::start::<Rpc, _>(client, &b"start".to_vec())
                .await
                .unwrap();
            assert_eq!(progress.next_progress().await, Some(b"one".to_vec()));
            assert_eq!(progress.next_progress().await, Some(b"two".to_vec()));
            assert_eq!(progress.next_progress().await, None);
            assert_eq!(progress.await.unwrap(), b"done".to_vec());
        };
        let server = progress::handle_progress::<(), Rpc, _, _, _, _>(
            (),
            CONTEXT,
            RouterConfig::default(),
            server,
            |(), _, request, mut responder| async move {
                assert_eq!(request, b"start".to_vec());
                responder.send(b"one".to_vec()).await.unwrap();
                responder.send(b"two".to_vec()).await.unwrap();
                responder.finish(b"done".to_vec()).await.unwrap();
            },
            |_, error| panic!("progress failed: {error:?}"),
        );
        run(client, server);
    }
}

#[test]
fn download() {
    struct Rpc;
    route!(Rpc, 5);

    impl download::Download for Rpc {
        type Error = Infallible;
        type Request = Vec<u8>;
        type ResponseHeader = Vec<u8>;
        type PartHeader = Vec<u8>;
    }

    for chunk_size in chunk_sizes() {
        let (client, server) = stream_pair(chunk_size);
        let client = async move {
            let download = download::start::<Rpc, _>(client, &b"file".to_vec())
                .await
                .unwrap();
            let (header, mut reader) = download.start().await.unwrap();
            assert_eq!(header, b"metadata".to_vec());
            let (header, mut part) = reader.next_part().await.unwrap().unwrap();
            assert_eq!(header, b"part".to_vec());
            let mut body = Vec::new();
            loop {
                let chunk = part.read_chunk().await.unwrap();
                if chunk.is_empty() {
                    break;
                }
                body.extend_from_slice(&chunk);
            }
            assert_eq!(body, b"abcdef".to_vec());
            drop(part);
            reader.complete().await.unwrap();
        };
        let server = download::handle_download::<(), Rpc, _, _, _, _>(
            (),
            CONTEXT,
            RouterConfig::default(),
            server,
            |(), _, request, download| async move {
                assert_eq!(request, b"file".to_vec());
                let mut writer = download.start(b"metadata".to_vec()).await.unwrap();
                let mut part = writer.start_part(b"part".to_vec()).await.unwrap();
                part.send(Bytes::from_static(b"abc")).await.unwrap();
                part.send(Bytes::from_static(b"def")).await.unwrap();
                part.finish().await.unwrap();
                writer.finish().await.unwrap();
            },
            |_, error| panic!("download failed: {error:?}"),
        );
        run(client, server);
    }
}

#[test]
fn upload() {
    struct Rpc;
    route!(Rpc, 6);

    impl upload::Upload for Rpc {
        type Error = Infallible;
        type Request = Vec<u8>;
        type PartHeader = Vec<u8>;
        type Response = Vec<u8>;
    }

    for chunk_size in chunk_sizes() {
        let (client, server) = stream_pair(chunk_size);
        let client = async move {
            let mut upload = upload::start::<Rpc, _>(client, &b"file".to_vec())
                .await
                .unwrap();
            let mut part = upload.start_part(b"part".to_vec()).await.unwrap();
            part.send(Bytes::from_static(b"abc")).await.unwrap();
            part.send(Bytes::from_static(b"def")).await.unwrap();
            part.finish().await.unwrap();
            assert_eq!(upload.finish().await.unwrap(), b"stored".to_vec());
        };
        let server = upload::handle_upload::<Rpc, (), _, _, _, _>(
            (),
            CONTEXT,
            RouterConfig {
                max_request_bytes: 4,
            },
            server,
            |(), _, request, mut upload, responder| async move {
                assert_eq!(request, b"file".to_vec());
                let (header, mut part) = upload.next_part().await.unwrap().unwrap();
                assert_eq!(header, b"part".to_vec());
                let mut body = Vec::new();
                loop {
                    let chunk = part.read_chunk().await.unwrap();
                    if chunk.is_empty() {
                        break;
                    }
                    body.extend_from_slice(&chunk);
                }
                assert_eq!(body, b"abcdef".to_vec());
                drop(part);
                upload.complete().await.unwrap();
                responder.respond(b"stored".to_vec()).await.unwrap();
            },
            |_, error| panic!("upload failed: {error:?}"),
        );
        run(client, server);
    }
}

#[test]
fn duplex() {
    struct Rpc;
    route!(Rpc, 7);

    impl duplex::Duplex for Rpc {
        type Error = Infallible;
        type InitiatorEvent = Vec<u8>;
        type ResponderEvent = Vec<u8>;
    }

    for chunk_size in chunk_sizes() {
        let (client, server) = stream_pair(chunk_size);
        let client = async move {
            let call = duplex::start::<Rpc, _>(client);
            let mut sender = call.sender;
            let mut receiver = call.receiver;
            sender.send(&b"ping".to_vec()).await.unwrap();
            sender.finish().await.unwrap();
            assert_eq!(
                receiver.next_event().await.unwrap().unwrap(),
                b"pong".to_vec()
            );
            assert!(receiver.next_event().await.is_none());
        };
        let server = duplex::handle_duplex::<(), Rpc, _, _, _>(
            (),
            CONTEXT,
            RouterConfig::default(),
            server,
            |(), _, mut peer| async move {
                assert_eq!(
                    peer.receiver.next_event().await.unwrap().unwrap(),
                    b"ping".to_vec()
                );
                assert!(peer.receiver.next_event().await.is_none());
                peer.sender.send(&b"pong".to_vec()).await.unwrap();
                peer.sender.finish().await.unwrap();
            },
        );
        run(client, server);
    }
}
