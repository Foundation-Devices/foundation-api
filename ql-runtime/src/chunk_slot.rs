use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use concurrent_queue::{ConcurrentQueue, PopError, PushError};
use event_listener::{Event, EventListener};

mod sync {
    #[cfg(not(all(test, loom)))]
    pub use std::sync::Arc;

    #[cfg(all(test, loom))]
    pub use loom::sync::Arc;
}

use sync::*;

/// creates a single-chunk handoff pair
/// receiver-side partial reads keep the remainder locally
pub fn new() -> (ChunkSlotRx, ChunkSlotTx) {
    let shared = Arc::new(Shared {
        queue: ConcurrentQueue::bounded(1),
        changed: Event::new(),
    });

    (
        ChunkSlotRx {
            shared: Arc::clone(&shared),
            pending: Bytes::new(),
        },
        ChunkSlotTx { shared },
    )
}

pub struct ChunkSlotRx {
    shared: Arc<Shared>,
    pending: Bytes,
}

pub struct ChunkSlotTx {
    shared: Arc<Shared>,
}

struct Shared {
    queue: ConcurrentQueue<Bytes>,
    changed: Event,
}

#[derive(Debug)]
pub struct SendClosed(pub Bytes);

#[derive(Debug, PartialEq, Eq)]
pub enum TrySendError {
    Closed(Bytes),
    Full(Bytes),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvClosed;

impl ChunkSlotRx {
    pub fn try_recv(&mut self, max_len: usize) -> Result<Bytes, RecvClosed> {
        if !self.pending.is_empty() {
            let pending = &mut self.pending;
            let bytes = if pending.len() <= max_len {
                std::mem::take(pending)
            } else {
                pending.split_to(max_len)
            };
            return Ok(bytes);
        }

        match self.shared.queue.pop() {
            Ok(mut bytes) => {
                self.shared.changed.notify(usize::MAX);
                let pending = &mut self.pending;

                let bytes = if bytes.len() <= max_len {
                    bytes
                } else {
                    let head = bytes.split_to(max_len);
                    *pending = bytes;
                    head
                };
                Ok(bytes)
            }
            Err(PopError::Empty) => Ok(Bytes::new()),
            Err(PopError::Closed) => Err(RecvClosed),
        }
    }

    pub fn poll_recv(
        &mut self,
        max_len: usize,
        listener: &mut Option<EventListener>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Bytes, RecvClosed>> {
        loop {
            match self.try_recv(max_len) {
                Ok(bytes) if !bytes.is_empty() => return Poll::Ready(Ok(bytes)),
                Err(closed) => return Poll::Ready(Err(closed)),
                Ok(_) => {}
            }

            if let Some(active_listener) = listener.as_mut() {
                match Pin::new(active_listener).poll(cx) {
                    Poll::Ready(()) => *listener = None,
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                *listener = Some(self.shared.changed.listen());
            }
        }
    }

    pub fn recv(&mut self, max_len: usize) -> Recv<'_> {
        Recv {
            rx: self,
            max_len,
            listener: None,
        }
    }

    pub fn is_finished(&self) -> bool {
        self.pending.is_empty() && self.shared.queue.is_closed() && self.shared.queue.is_empty()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.shared.queue.is_empty()
    }

    pub fn close(self) {
        if self.shared.queue.close() {
            self.shared.changed.notify(usize::MAX);
        }
    }
}

impl Drop for ChunkSlotRx {
    fn drop(&mut self) {
        if self.shared.queue.close() {
            self.shared.changed.notify(usize::MAX);
        }
    }
}

impl ChunkSlotTx {
    pub fn try_send(&self, bytes: Bytes) -> Result<(), TrySendError> {
        match self.shared.queue.push(bytes) {
            Ok(()) => {
                self.shared.changed.notify(usize::MAX);
                Ok(())
            }
            Err(PushError::Full(bytes)) => Err(TrySendError::Full(bytes)),
            Err(PushError::Closed(bytes)) => Err(TrySendError::Closed(bytes)),
        }
    }

    pub fn poll_send(
        &self,
        bytes: &mut Bytes,
        listener: &mut Option<EventListener>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), SendClosed>> {
        loop {
            let chunk = std::mem::take(bytes);
            match self.try_send(chunk) {
                Ok(()) => return Poll::Ready(Ok(())),
                Err(TrySendError::Closed(chunk)) => {
                    *bytes = chunk.clone();
                    return Poll::Ready(Err(SendClosed(chunk)));
                }
                Err(TrySendError::Full(chunk)) => *bytes = chunk,
            }

            if let Some(active_listener) = listener.as_mut() {
                match Pin::new(active_listener).poll(cx) {
                    Poll::Ready(()) => *listener = None,
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                *listener = Some(self.shared.changed.listen());
            }
        }
    }

    pub fn send(&self, bytes: Bytes) -> Send<'_> {
        Send {
            tx: self,
            bytes,
            listener: None,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.shared.queue.is_closed()
    }

    pub fn close(self) {
        if self.shared.queue.close() {
            self.shared.changed.notify(usize::MAX);
        }
    }
}

impl Drop for ChunkSlotTx {
    fn drop(&mut self) {
        if self.shared.queue.close() {
            self.shared.changed.notify(usize::MAX);
        }
    }
}

pub struct Recv<'a> {
    rx: &'a mut ChunkSlotRx,
    max_len: usize,
    listener: Option<EventListener>,
}

impl Future for Recv<'_> {
    type Output = Result<Bytes, RecvClosed>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        this.rx.poll_recv(this.max_len, &mut this.listener, cx)
    }
}

pub struct Send<'a> {
    tx: &'a ChunkSlotTx,
    bytes: Bytes,
    listener: Option<EventListener>,
}

impl Future for Send<'_> {
    type Output = Result<(), SendClosed>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        this.tx.poll_send(&mut this.bytes, &mut this.listener, cx)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;

    use super::{new, RecvClosed};

    #[test]
    fn try_send_and_take_round_trip() {
        let (mut rx, tx) = new();

        tx.try_send(Bytes::from_static(b"hello")).unwrap();
        assert_eq!(rx.try_recv(8), Ok(Bytes::from_static(b"hello")));
        assert_eq!(rx.try_recv(8), Ok(Bytes::new()));
    }

    #[test]
    fn read_splits_moves_remainder_to_receiver() {
        let (mut rx, tx) = new();

        tx.try_send(Bytes::from_static(b"hello")).unwrap();
        assert_eq!(rx.try_recv(2), Ok(Bytes::from_static(b"he")));
        tx.try_send(Bytes::from_static(b"!")).unwrap();
        assert_eq!(rx.try_recv(8), Ok(Bytes::from_static(b"llo")));
        assert_eq!(rx.try_recv(8), Ok(Bytes::from_static(b"!")));
    }

    #[test]
    fn read_drains_slot_when_limit_covers_chunk() {
        let (mut rx, tx) = new();

        tx.try_send(Bytes::from_static(b"hello")).unwrap();
        assert_eq!(rx.try_recv(8), Ok(Bytes::from_static(b"hello")));
        tx.try_send(Bytes::from_static(b"!")).unwrap();
        assert_eq!(rx.try_recv(8), Ok(Bytes::from_static(b"!")));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn send_waits_until_slot_clears() {
        let (mut rx, tx) = new();

        tx.try_send(Bytes::from_static(b"a")).unwrap();

        let sender = tokio::spawn(async move {
            tx.send(Bytes::from_static(b"b")).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(rx.try_recv(8), Ok(Bytes::from_static(b"a")));

        tokio::time::timeout(Duration::from_secs(1), sender)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn finish_yields_eof_after_buffered_chunk() {
        let (mut rx, tx) = new();

        tx.send(Bytes::from_static(b"abc")).await.unwrap();
        tx.close();

        assert_eq!(rx.recv(8).await, Ok(Bytes::from_static(b"abc")));
        assert_eq!(rx.recv(8).await, Err(RecvClosed));
        assert!(rx.is_finished());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn closing_receiver_returns_unsent_bytes() {
        let (rx, tx) = new();

        rx.close();

        let error = tx.send(Bytes::from_static(b"abc")).await.unwrap_err();
        assert_eq!(error.0, Bytes::from_static(b"abc"));
    }

    #[test]
    fn zero_length_recv_does_not_consume_buffered_chunk() {
        let (mut rx, tx) = new();

        tx.try_send(Bytes::from_static(b"hello")).unwrap();
        assert_eq!(rx.try_recv(0), Ok(Bytes::new()));
        assert_eq!(rx.try_recv(8), Ok(Bytes::from_static(b"hello")));
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    use std::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    use bytes::Bytes;
    use loom::{model, thread};

    use super::{new, RecvClosed};

    fn now_or_never<F: Future>(future: F) -> Option<F::Output> {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => Some(value),
            Poll::Pending => None,
        }
    }

    fn check_model(f: impl Fn() + Sync + Send + 'static) {
        let mut builder = model::Builder::new();
        builder.preemption_bound = Some(3);
        builder.check(f);
    }

    #[test]
    fn try_recv_never_reports_closed_while_open() {
        check_model(|| {
            let (mut rx, tx) = new();

            let sender = thread::spawn(move || {
                let _ = tx.try_send(Bytes::from_static(b"abc"));
            });

            let receiver = thread::spawn(move || {
                let result = rx.try_recv(1);
                assert!(
                    !matches!(result, Err(RecvClosed)),
                    "open slot must not report RecvClosed"
                );
            });

            sender.join().unwrap();
            receiver.join().unwrap();
        });
    }

    #[test]
    fn recv_observes_send_after_pending() {
        check_model(|| {
            let (mut rx, tx) = new();

            assert!(now_or_never(rx.recv(8)).is_none());

            let sender = thread::spawn(move || {
                tx.try_send(Bytes::from_static(b"abc")).unwrap();
            });

            sender.join().unwrap();

            assert_eq!(
                now_or_never(rx.recv(8)),
                Some(Ok(Bytes::from_static(b"abc")))
            );
        });
    }

    #[test]
    fn recv_observes_finish_as_closed() {
        check_model(|| {
            let (mut rx, tx) = new();

            assert!(now_or_never(rx.recv(8)).is_none());

            let finisher = thread::spawn(move || {
                tx.close();
            });

            finisher.join().unwrap();

            assert_eq!(now_or_never(rx.recv(8)), Some(Err(RecvClosed)));
        });
    }

    #[test]
    fn partial_recv_preserves_remainder_and_finished_state() {
        check_model(|| {
            let (mut rx, tx) = new();

            tx.try_send(Bytes::from_static(b"abcd")).unwrap();
            tx.close();

            assert_eq!(rx.try_recv(2), Ok(Bytes::from_static(b"ab")));
            assert!(!rx.is_finished());
            assert_eq!(rx.try_recv(8), Ok(Bytes::from_static(b"cd")));
            assert_eq!(rx.try_recv(8), Err(RecvClosed));
            assert!(rx.is_finished());
        });
    }
}
