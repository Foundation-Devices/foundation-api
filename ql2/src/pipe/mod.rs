use std::{
    cell::UnsafeCell,
    io::{self, Read},
    mem::{self, MaybeUninit},
    ptr,
    sync::{
        atomic::{AtomicU64, AtomicU8, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use atomic_waker::AtomicWaker;
use futures_lite::future::poll_fn;

const PIPE_OPEN: u8 = 0;
const PIPE_FINISHED: u8 = 1;
const PIPE_FAILED: u8 = 2;
const PIPE_FAILED_TAKEN: u8 = 3;
const PIPE_CLOSED: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipeState {
    Open,
    Finished,
    Failed,
    FailedTaken,
    Closed,
}

impl PipeState {
    fn from_u8(value: u8) -> Self {
        match value {
            PIPE_OPEN => Self::Open,
            PIPE_FINISHED => Self::Finished,
            PIPE_FAILED => Self::Failed,
            PIPE_FAILED_TAKEN => Self::FailedTaken,
            PIPE_CLOSED => Self::Closed,
            _ => unreachable!("invalid pipe state"),
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Open => PIPE_OPEN,
            Self::Finished => PIPE_FINISHED,
            Self::Failed => PIPE_FAILED,
            Self::FailedTaken => PIPE_FAILED_TAKEN,
            Self::Closed => PIPE_CLOSED,
        }
    }
}

pub(crate) fn pipe<E>(cap: usize) -> (PipeReader<E>, PipeWriter<E>) {
    assert!(cap > 0, "pipe capacity must be positive");

    let mut storage = Vec::<u8>::with_capacity(cap);
    let buffer = storage.as_mut_ptr();
    mem::forget(storage);

    let inner = Arc::new(PipeInner {
        released: AtomicU64::new(0),
        produced: AtomicU64::new(0),
        state: AtomicU8::new(PIPE_OPEN),
        error: UnsafeCell::new(MaybeUninit::uninit()),
        readable: AtomicWaker::new(),
        writable: AtomicWaker::new(),
        closed: AtomicWaker::new(),
        buffer,
        cap,
    });

    (
        PipeReader {
            inner: inner.clone(),
            released: 0,
            produced: 0,
            sent: 0,
        },
        PipeWriter {
            inner,
            released: 0,
            produced: 0,
            sealed: false,
        },
    )
}

struct PipeInner<E> {
    released: AtomicU64,
    produced: AtomicU64,
    state: AtomicU8,
    error: UnsafeCell<MaybeUninit<E>>,
    readable: AtomicWaker,
    writable: AtomicWaker,
    closed: AtomicWaker,
    buffer: *mut u8,
    cap: usize,
}

unsafe impl<E: Send> Send for PipeInner<E> {}
unsafe impl<E: Send> Sync for PipeInner<E> {}

impl<E> Drop for PipeInner<E> {
    fn drop(&mut self) {
        if PipeState::from_u8(self.state.load(Ordering::Acquire)) == PipeState::Failed {
            unsafe {
                self.error.get_mut().assume_init_drop();
            }
        }
        unsafe {
            drop(Vec::from_raw_parts(self.buffer, 0, self.cap));
        }
    }
}

pub(crate) struct PipeWriter<E> {
    inner: Arc<PipeInner<E>>,
    released: u64,
    produced: u64,
    sealed: bool,
}

pub(crate) struct PipeReader<E> {
    inner: Arc<PipeInner<E>>,
    released: u64,
    produced: u64,
    sent: u64,
}

impl<E> std::fmt::Debug for PipeWriter<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeWriter").finish_non_exhaustive()
    }
}

impl<E> std::fmt::Debug for PipeReader<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeReader").finish_non_exhaustive()
    }
}

pub(crate) struct SendGrant<'a, E> {
    inner: &'a PipeInner<E>,
    offset: u64,
    len: usize,
    position: usize,
}

pub(crate) enum ReadReady<E> {
    Data,
    Eof,
    Error(E),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PipeClosed;

impl<E> PipeWriter<E> {
    pub fn try_write(&mut self, src: &[u8]) -> Result<usize, PipeClosed> {
        if src.is_empty() {
            return Ok(0);
        }
        if self.sealed || self.is_closed() {
            return Err(PipeClosed);
        }
        self.released = self.inner.released.load(Ordering::Acquire);
        let n = self.available_capacity().min(src.len());
        if n == 0 {
            return Ok(0);
        }
        unsafe {
            write_bytes(self.inner.buffer, self.inner.cap, self.produced, &src[..n]);
        }
        self.produced = self.produced.saturating_add(n as u64);
        self.inner.produced.store(self.produced, Ordering::Release);
        self.inner.readable.wake();
        Ok(n)
    }

    pub fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<Result<usize, PipeClosed>> {
        if src.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.sealed || self.is_closed() {
            return Poll::Ready(Err(PipeClosed));
        }

        let n = match self.poll_reserve(cx, src.len()) {
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        };

        unsafe {
            write_bytes(self.inner.buffer, self.inner.cap, self.produced, &src[..n]);
        }
        self.produced = self.produced.saturating_add(n as u64);
        self.inner.produced.store(self.produced, Ordering::Release);
        self.inner.readable.wake();
        Poll::Ready(Ok(n))
    }

    pub fn finish(&mut self) {
        if self.sealed {
            return;
        }
        self.sealed = true;
        self.publish_state(PipeState::Finished);
    }

    pub fn fail(&mut self, error: E) {
        if self.sealed {
            return;
        }
        self.sealed = true;
        unsafe {
            (*self.inner.error.get()).write(error);
        }
        match self.inner.state.compare_exchange(
            PIPE_OPEN,
            PIPE_FAILED,
            Ordering::Release,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                self.inner.readable.wake();
            }
            Err(_) => unsafe {
                (*self.inner.error.get()).assume_init_drop();
            },
        }
    }

    pub fn close(&mut self) {
        if self.sealed {
            return;
        }
        self.sealed = true;
        loop {
            let current = PipeState::from_u8(self.inner.state.load(Ordering::Acquire));
            match current {
                PipeState::Closed => return,
                PipeState::Failed => {
                    if self.inner.state.compare_exchange(
                        PIPE_FAILED,
                        PIPE_CLOSED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ).is_ok() {
                        unsafe {
                            (*self.inner.error.get()).assume_init_drop();
                        }
                        self.inner.readable.wake();
                        self.inner.writable.wake();
                        self.inner.closed.wake();
                        return;
                    }
                }
                _ => {
                    if self.inner.state.compare_exchange(
                        current.as_u8(),
                        PIPE_CLOSED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ).is_ok() {
                        self.inner.readable.wake();
                        self.inner.writable.wake();
                        self.inner.closed.wake();
                        return;
                    }
                }
            }
        }
    }

    pub fn poll_closed(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.is_closed() {
            return Poll::Ready(());
        }
        self.inner.closed.register(cx.waker());
        if self.is_closed() {
            self.inner.closed.take();
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    pub async fn closed(&mut self) {
        poll_fn(|cx| self.poll_closed(cx)).await
    }

    fn poll_reserve(
        &mut self,
        cx: &mut Context<'_>,
        want: usize,
    ) -> Poll<Result<usize, PipeClosed>> {
        self.released = self.inner.released.load(Ordering::Acquire);
        let available = self.available_capacity();
        if available > 0 {
            return Poll::Ready(Ok(available.min(want)));
        }

        self.inner.writable.register(cx.waker());
        self.released = self.inner.released.load(Ordering::Acquire);
        if self.is_closed() {
            self.inner.writable.take();
            return Poll::Ready(Err(PipeClosed));
        }
        let available = self.available_capacity();
        if available > 0 {
            self.inner.writable.take();
            Poll::Ready(Ok(available.min(want)))
        } else {
            Poll::Pending
        }
    }

    fn available_capacity(&self) -> usize {
        let used = self.produced.saturating_sub(self.released) as usize;
        self.inner.cap.saturating_sub(used)
    }

    fn publish_state(&mut self, next: PipeState) {
        let _ = self.inner.state.compare_exchange(
            PIPE_OPEN,
            next.as_u8(),
            Ordering::Release,
            Ordering::Acquire,
        );
        self.inner.readable.wake();
    }

    fn is_closed(&self) -> bool {
        PipeState::from_u8(self.inner.state.load(Ordering::Acquire)) == PipeState::Closed
    }

    pub fn state(&self) -> PipeState {
        PipeState::from_u8(self.inner.state.load(Ordering::Acquire))
    }

    pub fn is_drained(&self) -> bool {
        self.inner.released.load(Ordering::Acquire) >= self.inner.produced.load(Ordering::Acquire)
    }
}

impl<E> Drop for PipeWriter<E> {
    fn drop(&mut self) {
        if self.sealed {
            return;
        }
        self.sealed = true;
        self.publish_state(PipeState::Finished);
    }
}

impl<E> PipeReader<E> {
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<ReadReady<E>> {
        self.produced = self.inner.produced.load(Ordering::Acquire);
        if self.available_data() > 0 {
            return Poll::Ready(ReadReady::Data);
        }

        loop {
            match PipeState::from_u8(self.inner.state.load(Ordering::Acquire)) {
                PipeState::Open => {
                    self.inner.readable.register(cx.waker());
                    self.produced = self.inner.produced.load(Ordering::Acquire);
                    if self.available_data() > 0 {
                        self.inner.readable.take();
                        return Poll::Ready(ReadReady::Data);
                    }
                    if PipeState::from_u8(self.inner.state.load(Ordering::Acquire))
                        == PipeState::Open
                    {
                        return Poll::Pending;
                    }
                    self.inner.readable.take();
                }
                PipeState::Finished | PipeState::Closed => return Poll::Ready(ReadReady::Eof),
                PipeState::Failed => {
                    let err = match self.inner.state.compare_exchange(
                        PIPE_FAILED,
                        PIPE_FAILED_TAKEN,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => unsafe { (*self.inner.error.get()).assume_init_read() },
                        Err(_) => continue,
                    };
                    return Poll::Ready(ReadReady::Error(err));
                }
                PipeState::FailedTaken => return Poll::Ready(ReadReady::Eof),
            }
        }
    }

    pub fn peek_buf(&self) -> &[u8] {
        let len = self.available_data().min(self.inner.cap - ((self.released as usize) % self.inner.cap));
        unsafe { ptr::slice_from_raw_parts(self.inner.buffer.add((self.released as usize) % self.inner.cap), len).as_ref().unwrap() }
    }

    pub fn consume(&mut self, amt: usize) {
        assert!(amt <= self.available_data(), "cannot consume more bytes than available");
        self.released = self.released.saturating_add(amt as u64);
        self.inner.released.store(self.released, Ordering::Release);
        if self.sent < self.released {
            self.sent = self.released;
        }
        self.inner.writable.wake();
    }

    pub fn reserve_send(&mut self, remote_max_offset: u64, max_len: usize) -> Option<SendGrant<'_, E>> {
        self.produced = self.inner.produced.load(Ordering::Acquire);
        let limit = self.produced.min(remote_max_offset);
        if self.sent >= limit {
            return None;
        }
        let len = ((limit - self.sent) as usize).min(max_len);
        let offset = self.sent;
        self.sent = self.sent.saturating_add(len as u64);
        Some(SendGrant {
            inner: self.inner.as_ref(),
            offset,
            len,
            position: 0,
        })
    }

    pub fn retry_send(&self, offset: u64, len: usize) -> Option<SendGrant<'_, E>> {
        let released = self.inner.released.load(Ordering::Acquire);
        let produced = self.inner.produced.load(Ordering::Acquire);
        if offset < released || offset.saturating_add(len as u64) > produced {
            return None;
        }
        Some(SendGrant {
            inner: self.inner.as_ref(),
            offset,
            len,
            position: 0,
        })
    }

    pub fn release_to(&mut self, released: u64) {
        self.released = released;
        self.inner.released.store(released, Ordering::Release);
        self.inner.writable.wake();
    }

    pub fn released_offset(&self) -> u64 {
        self.released
    }

    pub fn sent_offset(&self) -> u64 {
        self.sent
    }

    pub fn writer_finished(&self) -> bool {
        PipeState::from_u8(self.inner.state.load(Ordering::Acquire)) == PipeState::Finished
    }

    pub fn all_sent(&mut self) -> bool {
        self.produced = self.inner.produced.load(Ordering::Acquire);
        self.sent >= self.produced
    }

    pub fn close(&mut self) {
        loop {
            match PipeState::from_u8(self.inner.state.load(Ordering::Acquire)) {
                PipeState::Closed => return,
                PipeState::Failed => {
                    if self.inner.state.compare_exchange(
                        PIPE_FAILED,
                        PIPE_CLOSED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ).is_ok() {
                        unsafe {
                            (*self.inner.error.get()).assume_init_drop();
                        }
                        self.inner.writable.wake();
                        self.inner.closed.wake();
                        return;
                    }
                }
                current => {
                    if self.inner.state.compare_exchange(
                        current.as_u8(),
                        PIPE_CLOSED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ).is_ok() {
                        self.inner.writable.wake();
                        self.inner.closed.wake();
                        return;
                    }
                }
            }
        }
    }

    fn available_data(&self) -> usize {
        self.produced.saturating_sub(self.released) as usize
    }

    pub fn state(&self) -> PipeState {
        PipeState::from_u8(self.inner.state.load(Ordering::Acquire))
    }
}

impl<E> Drop for PipeReader<E> {
    fn drop(&mut self) {
        self.close();
    }
}

impl<E> SendGrant<'_, E> {
    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl<E> Read for SendGrant<'_, E> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.len.saturating_sub(self.position);
        if remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let n = remaining.min(buf.len());
        unsafe {
            copy_bytes(
                self.inner.buffer,
                self.inner.cap,
                self.offset.saturating_add(self.position as u64),
                &mut buf[..n],
            );
        }
        self.position += n;
        Ok(n)
    }
}

unsafe fn write_bytes(buffer: *mut u8, cap: usize, offset: u64, src: &[u8]) {
    let start = (offset as usize) % cap;
    let first = src.len().min(cap - start);
    ptr::copy_nonoverlapping(src.as_ptr(), buffer.add(start), first);
    if first < src.len() {
        ptr::copy_nonoverlapping(src[first..].as_ptr(), buffer, src.len() - first);
    }
}

unsafe fn copy_bytes(buffer: *mut u8, cap: usize, offset: u64, dst: &mut [u8]) {
    let len = dst.len();
    let start = (offset as usize) % cap;
    let first = len.min(cap - start);
    ptr::copy_nonoverlapping(buffer.add(start), dst.as_mut_ptr(), first);
    if first < len {
        ptr::copy_nonoverlapping(buffer, dst.as_mut_ptr().add(first), len - first);
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use futures_lite::future::poll_fn;
    use tokio::task::yield_now;

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn pipe_writes_reads_and_releases() {
        let (mut reader, mut writer) = pipe::<Infallible>(8);
        assert_eq!(poll_fn(|cx| writer.poll_write(cx, b"abcd")).await.unwrap(), 4);

        let mut send = reader.reserve_send(8, 8).unwrap();
        assert_eq!(send.offset(), 0);
        assert_eq!(send.len(), 4);
        let mut bytes = vec![0; send.len()];
        send.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, b"abcd");

        reader.release_to(4);
        assert!(writer.is_drained());
        assert_eq!(poll_fn(|cx| writer.poll_write(cx, b"ef")).await.unwrap(), 2);
        let mut send = reader.reserve_send(8, 8).unwrap();
        let mut bytes = vec![0; send.len()];
        send.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, b"ef");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pipe_blocks_until_released() {
        let (mut reader, mut writer) = pipe::<Infallible>(4);
        assert_eq!(poll_fn(|cx| writer.poll_write(cx, b"abcd")).await.unwrap(), 4);

        let mut blocked = false;
        let poll = poll_fn(|cx| match writer.poll_write(cx, b"e") {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => {
                blocked = true;
                Poll::Ready(Ok(0))
            }
        })
        .await
        .unwrap();
        assert_eq!(poll, 0);
        assert!(blocked);

        reader.release_to(4);
        yield_now().await;
        assert_eq!(poll_fn(|cx| writer.poll_write(cx, b"e")).await.unwrap(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pipe_closed_waits_for_reader_close() {
        let (mut reader, mut writer) = pipe::<Infallible>(8);
        writer.finish();
        assert_eq!(writer.state(), PipeState::Finished);

        let waiter = tokio::spawn(async move {
            writer.closed().await;
        });

        yield_now().await;
        assert!(!waiter.is_finished());
        reader.close();
        waiter.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pipe_wraparound_reads_correctly() {
        let (mut reader, mut writer) = pipe::<Infallible>(8);
        assert_eq!(poll_fn(|cx| writer.poll_write(cx, b"abcdef")).await.unwrap(), 6);
        let mut send = reader.reserve_send(8, 6).unwrap();
        let mut bytes = vec![0; send.len()];
        send.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, b"abcdef");
        reader.release_to(6);

        assert_eq!(poll_fn(|cx| writer.poll_write(cx, b"ghijkl")).await.unwrap(), 6);
        let mut send = reader.reserve_send(12, 6).unwrap();
        let mut bytes = vec![0; send.len()];
        send.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, b"ghijkl");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn closing_reader_wakes_writer() {
        let (mut reader, mut writer) = pipe::<Infallible>(4);
        assert_eq!(poll_fn(|cx| writer.poll_write(cx, b"abcd")).await.unwrap(), 4);
        reader.close();
        assert_eq!(reader.state(), PipeState::Closed);
        let err = poll_fn(|cx| writer.poll_write(cx, b"e")).await.unwrap_err();
        assert_eq!(err, PipeClosed);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn buffered_bytes_drain_before_eof() {
        let (mut reader, mut writer) = pipe::<Infallible>(8);
        poll_fn(|cx| writer.poll_write(cx, b"abc")).await.unwrap();
        writer.finish();

        assert!(matches!(poll_fn(|cx| reader.poll_ready(cx)).await, ReadReady::Data));
        assert_eq!(reader.peek_buf(), b"abc");
        reader.consume(3);
        assert!(matches!(poll_fn(|cx| reader.poll_ready(cx)).await, ReadReady::Eof));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn buffered_bytes_drain_before_error() {
        let (mut reader, mut writer) = pipe::<&'static str>(8);
        poll_fn(|cx| writer.poll_write(cx, b"abc")).await.unwrap();
        writer.fail("boom");

        assert!(matches!(poll_fn(|cx| reader.poll_ready(cx)).await, ReadReady::Data));
        assert_eq!(reader.peek_buf(), b"abc");
        reader.consume(3);
        match poll_fn(|cx| reader.poll_ready(cx)).await {
            ReadReady::Error(err) => assert_eq!(err, "boom"),
            _ => panic!("expected pipe error"),
        }
    }
}
