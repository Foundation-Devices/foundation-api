use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use event_listener::{Event, EventListener};

mod sync {
    #[cfg(not(all(test, loom)))]
    pub use std::sync::atomic::{AtomicU8, Ordering};
    #[cfg(not(all(test, loom)))]
    pub use std::sync::{Arc, Mutex};

    #[cfg(all(test, loom))]
    pub use loom::sync::atomic::{AtomicU8, Ordering};
    #[cfg(all(test, loom))]
    pub use loom::sync::{Arc, Mutex};
}

use sync::{Arc, AtomicU8, Mutex, Ordering};

const OCCUPIED: u8 = 1 << 0;
const TX_CLOSED: u8 = 1 << 1;
const RX_CLOSED: u8 = 1 << 2;

pub fn new() -> (ChunkSlotRx, ChunkSlotTx) {
    let inner = Arc::new(Inner {
        chunk: Mutex::new(None),
        state: AtomicU8::new(0),
        changed: Event::new(),
    });

    (
        ChunkSlotRx {
            inner: inner.clone(),
        },
        ChunkSlotTx { inner },
    )
}

pub struct ChunkSlotRx {
    inner: Arc<Inner>,
}

pub struct ChunkSlotTx {
    inner: Arc<Inner>,
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
    pub fn try_recv(&self, max_len: usize) -> Result<Option<Bytes>, RecvClosed> {
        self.inner.try_recv(max_len)
    }

    pub fn poll_recv(
        &self,
        max_len: usize,
        listener: &mut Option<EventListener>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Bytes, RecvClosed>> {
        loop {
            match self.try_recv(max_len) {
                Ok(Some(bytes)) => return Poll::Ready(Ok(bytes)),
                Err(closed) => return Poll::Ready(Err(closed)),
                Ok(None) => {}
            }

            if let Some(active_listener) = listener.as_mut() {
                match Pin::new(active_listener).poll(cx) {
                    Poll::Ready(()) => *listener = None,
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                *listener = Some(self.inner.changed.listen());
            }
        }
    }

    pub fn recv(&self, max_len: usize) -> Recv<'_> {
        Recv {
            rx: self,
            max_len,
            listener: None,
        }
    }

    pub fn is_finished(&self) -> bool {
        self.inner.snapshot(Ordering::Acquire).is_finished()
    }

    pub fn is_empty(&self) -> bool {
        !self.inner.snapshot(Ordering::Relaxed).is_occupied()
    }

    pub fn close(self) {
        self.inner.close_rx();
    }
}

impl Drop for ChunkSlotRx {
    fn drop(&mut self) {
        self.inner.close_rx();
    }
}

impl ChunkSlotTx {
    pub fn try_send(&self, bytes: Bytes) -> Result<(), TrySendError> {
        self.inner.try_send(bytes)
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
                *listener = Some(self.inner.changed.listen());
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
        self.inner.snapshot(Ordering::Acquire).is_closed()
    }

    pub fn close(self) {
        self.inner.close_tx();
    }
}

impl Drop for ChunkSlotTx {
    fn drop(&mut self) {
        self.inner.close_tx();
    }
}

pub struct Recv<'a> {
    rx: &'a ChunkSlotRx,
    max_len: usize,
    listener: Option<EventListener>,
}

impl Future for Recv<'_> {
    type Output = Result<Bytes, RecvClosed>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.rx.poll_recv(self.max_len, &mut self.listener, cx)
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

struct Inner {
    chunk: Mutex<Option<Bytes>>,
    state: AtomicU8,
    changed: Event,
}

#[derive(Clone, Copy)]
struct StateSnapshot(u8);

impl StateSnapshot {
    fn has_any(self, bits: u8) -> bool {
        self.0 & bits != 0
    }

    fn is_occupied(self) -> bool {
        self.has_any(OCCUPIED)
    }

    fn is_closed(self) -> bool {
        self.has_any(TX_CLOSED | RX_CLOSED)
    }

    fn is_finished(self) -> bool {
        self.has_any(TX_CLOSED) && !self.is_occupied()
    }
}

impl Inner {
    fn snapshot(&self, ordering: Ordering) -> StateSnapshot {
        StateSnapshot(self.state.load(ordering))
    }

    fn mark_occupied(&self) {
        self.state.fetch_or(OCCUPIED, Ordering::Release);
    }

    fn clear_occupied(&self) {
        self.state.fetch_and(!OCCUPIED, Ordering::Release);
    }

    fn close_rx(&self) {
        if !StateSnapshot(self.state.fetch_or(RX_CLOSED, Ordering::Release)).has_any(RX_CLOSED) {
            self.changed.notify(usize::MAX);
        }
    }

    fn close_tx(&self) {
        if !StateSnapshot(self.state.fetch_or(TX_CLOSED, Ordering::Release)).has_any(TX_CLOSED) {
            self.changed.notify(usize::MAX);
        }
    }

    fn try_recv(&self, max_len: usize) -> Result<Option<Bytes>, RecvClosed> {
        let snapshot = self.snapshot(Ordering::Acquire);
        if max_len == 0 || !snapshot.is_occupied() {
            return if snapshot.is_closed() {
                Err(RecvClosed)
            } else {
                Ok(None)
            };
        }

        let (bytes, became_empty) = {
            let Ok(mut chunk) = self.chunk.try_lock() else {
                return Ok(None);
            };
            let Some(result) = take_chunk(&mut chunk, max_len) else {
                return Ok(None);
            };
            result
        };

        if became_empty {
            self.clear_occupied();
            self.changed.notify(usize::MAX);
        }

        Ok(Some(bytes))
    }

    fn try_send(&self, bytes: Bytes) -> Result<(), TrySendError> {
        let snapshot = self.snapshot(Ordering::Acquire);
        if snapshot.is_closed() {
            return Err(TrySendError::Closed(bytes));
        }
        if snapshot.is_occupied() {
            return Err(TrySendError::Full(bytes));
        }

        let result = {
            let Ok(mut chunk) = self.chunk.try_lock() else {
                return Err(TrySendError::Full(bytes));
            };
            if self.snapshot(Ordering::Relaxed).is_closed() {
                Err(TrySendError::Closed(bytes))
            } else if chunk.is_some() {
                Err(TrySendError::Full(bytes))
            } else {
                *chunk = Some(bytes);
                Ok(())
            }
        };

        if result.is_ok() {
            self.mark_occupied();
            self.changed.notify(usize::MAX);
        }

        result
    }
}

fn take_chunk(chunk: &mut Option<Bytes>, max_len: usize) -> Option<(Bytes, bool)> {
    let bytes = chunk.as_mut()?;
    if bytes.len() <= max_len {
        Some((chunk.take().unwrap(), true))
    } else {
        Some((bytes.split_to(max_len), false))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;

    use super::{new, TrySendError};

    #[test]
    fn try_send_and_take_round_trip() {
        let (rx, tx) = new();

        tx.try_send(Bytes::from_static(b"hello")).unwrap();
        assert_eq!(rx.try_recv(8), Ok(Some(Bytes::from_static(b"hello"))));
        assert_eq!(rx.try_recv(8), Ok(None));
    }

    #[test]
    fn read_splits_without_freeing_slot() {
        let (rx, tx) = new();

        tx.try_send(Bytes::from_static(b"hello")).unwrap();
        assert_eq!(rx.try_recv(2), Ok(Some(Bytes::from_static(b"he"))));
        assert_eq!(
            tx.try_send(Bytes::from_static(b"!")),
            Err(TrySendError::Full(Bytes::from_static(b"!")))
        );
        assert_eq!(rx.try_recv(8), Ok(Some(Bytes::from_static(b"llo"))));
    }

    #[test]
    fn read_drains_slot_when_limit_covers_chunk() {
        let (rx, tx) = new();

        tx.try_send(Bytes::from_static(b"hello")).unwrap();
        assert_eq!(rx.try_recv(8), Ok(Some(Bytes::from_static(b"hello"))));
        tx.try_send(Bytes::from_static(b"!")).unwrap();
        assert_eq!(rx.try_recv(8), Ok(Some(Bytes::from_static(b"!"))));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn send_waits_until_slot_clears() {
        let (rx, tx) = new();

        tx.try_send(Bytes::from_static(b"a")).unwrap();

        let sender = tokio::spawn(async move {
            tx.send(Bytes::from_static(b"b")).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(rx.try_recv(8), Ok(Some(Bytes::from_static(b"a"))));

        tokio::time::timeout(Duration::from_secs(1), sender)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn finish_yields_eof_after_buffered_chunk() {
        let (rx, tx) = new();

        tx.send(Bytes::from_static(b"abc")).await.unwrap();
        tx.close();

        assert_eq!(rx.recv(8).await, Ok(Bytes::from_static(b"abc")));
        assert_eq!(rx.recv(8).await, Err(super::RecvClosed));
        assert!(rx.is_finished());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn closing_receiver_returns_unsent_bytes() {
        let (rx, tx) = new();

        rx.close();

        let error = tx.send(Bytes::from_static(b"abc")).await.unwrap_err();
        assert_eq!(error.0, Bytes::from_static(b"abc"));
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
            let (rx, tx) = new();

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
            let (rx, tx) = new();

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
            let (rx, tx) = new();

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
            let (rx, tx) = new();

            tx.try_send(Bytes::from_static(b"abcd")).unwrap();
            tx.close();

            assert_eq!(rx.try_recv(2), Ok(Some(Bytes::from_static(b"ab"))));
            assert!(!rx.is_finished());
            assert_eq!(rx.try_recv(8), Ok(Some(Bytes::from_static(b"cd"))));
            assert_eq!(rx.try_recv(8), Err(RecvClosed));
            assert!(rx.is_finished());
        });
    }
}
