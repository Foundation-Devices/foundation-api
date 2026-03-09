use std::{
    mem,
    ptr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use atomic_waker::AtomicWaker;
use futures_lite::future::poll_fn;

pub(crate) fn pipe(cap: usize) -> (PipeReader, PipeWriter) {
    assert!(cap > 0, "pipe capacity must be positive");

    let mut storage = Vec::<u8>::with_capacity(cap);
    let buffer = storage.as_mut_ptr();
    mem::forget(storage);

    let inner = Arc::new(PipeInner {
        acked: AtomicU64::new(0),
        written: AtomicU64::new(0),
        writer_finished: AtomicBool::new(false),
        reader_closed: AtomicBool::new(false),
        writable: AtomicWaker::new(),
        closed: AtomicWaker::new(),
        buffer,
        cap,
    });

    (
        PipeReader {
            inner: inner.clone(),
            acked: 0,
            written: 0,
            sent: 0,
        },
        PipeWriter {
            inner,
            acked: 0,
            written: 0,
            finished: false,
        },
    )
}

struct PipeInner {
    acked: AtomicU64,
    written: AtomicU64,
    writer_finished: AtomicBool,
    reader_closed: AtomicBool,
    writable: AtomicWaker,
    closed: AtomicWaker,
    buffer: *mut u8,
    cap: usize,
}

unsafe impl Send for PipeInner {}
unsafe impl Sync for PipeInner {}

impl Drop for PipeInner {
    fn drop(&mut self) {
        unsafe {
            drop(Vec::from_raw_parts(self.buffer, 0, self.cap));
        }
    }
}

pub(crate) struct PipeWriter {
    inner: Arc<PipeInner>,
    acked: u64,
    written: u64,
    finished: bool,
}

pub(crate) struct PipeReader {
    inner: Arc<PipeInner>,
    acked: u64,
    written: u64,
    sent: u64,
}

pub(crate) struct SendSlice {
    pub offset: u64,
    pub len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PipeClosed;

impl PipeWriter {
    pub fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<Result<usize, PipeClosed>> {
        if src.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.finished {
            return Poll::Ready(Err(PipeClosed));
        }
        if self.inner.reader_closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(PipeClosed));
        }

        let n = match self.poll_reserve(cx, src.len()) {
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        };

        unsafe {
            write_bytes(self.inner.buffer, self.inner.cap, self.written, &src[..n]);
        }
        self.written = self.written.saturating_add(n as u64);
        self.inner.written.store(self.written, Ordering::Release);
        Poll::Ready(Ok(n))
    }

    pub fn finish(&mut self) {
        self.finished = true;
        self.inner.writer_finished.store(true, Ordering::Release);
    }

    pub fn poll_closed(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.inner.reader_closed.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        self.inner.closed.register(cx.waker());
        if self.inner.reader_closed.load(Ordering::Acquire) {
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
        self.acked = self.inner.acked.load(Ordering::Acquire);
        let available = self.available_capacity();
        if available > 0 {
            return Poll::Ready(Ok(available.min(want)));
        }

        self.inner.writable.register(cx.waker());
        self.acked = self.inner.acked.load(Ordering::Acquire);
        if self.inner.reader_closed.load(Ordering::Acquire) {
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
        let used = self.written.saturating_sub(self.acked) as usize;
        self.inner.cap.saturating_sub(used)
    }
}

impl PipeReader {
    pub fn reserve_send(&mut self, remote_max_offset: u64, max_len: usize) -> Option<SendSlice> {
        self.written = self.inner.written.load(Ordering::Acquire);
        let limit = self.written.min(remote_max_offset);
        if self.sent >= limit {
            return None;
        }
        let len = ((limit - self.sent) as usize).min(max_len);
        let offset = self.sent;
        self.sent = self.sent.saturating_add(len as u64);
        Some(SendSlice { offset, len })
    }

    pub fn read_range(&self, offset: u64, len: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(len);
        unsafe {
            copy_bytes(self.inner.buffer, self.inner.cap, offset, len, &mut bytes);
        }
        bytes
    }

    pub fn ack_to(&mut self, recv_offset: u64) {
        self.acked = recv_offset;
        self.inner.acked.store(recv_offset, Ordering::Release);
        self.inner.writable.wake();
    }

    pub fn acked_offset(&self) -> u64 {
        self.acked
    }

    pub fn sent_offset(&self) -> u64 {
        self.sent
    }

    pub fn writer_finished(&self) -> bool {
        self.inner.writer_finished.load(Ordering::Acquire)
    }

    pub fn all_sent(&mut self) -> bool {
        self.written = self.inner.written.load(Ordering::Acquire);
        self.sent >= self.written
    }

    pub fn close(&mut self) {
        if !self.inner.reader_closed.swap(true, Ordering::Release) {
            self.inner.writable.wake();
            self.inner.closed.wake();
        }
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

unsafe fn copy_bytes(buffer: *mut u8, cap: usize, offset: u64, len: usize, dst: &mut Vec<u8>) {
    dst.set_len(len);
    let start = (offset as usize) % cap;
    let first = len.min(cap - start);
    ptr::copy_nonoverlapping(buffer.add(start), dst.as_mut_ptr(), first);
    if first < len {
        ptr::copy_nonoverlapping(buffer, dst.as_mut_ptr().add(first), len - first);
    }
}

#[cfg(test)]
mod tests {
    use futures_lite::future::poll_fn;
    use tokio::task::yield_now;

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn pipe_writes_reads_and_acks() {
        let (mut reader, mut writer) = pipe(8);
        assert_eq!(poll_fn(|cx| writer.poll_write(cx, b"abcd")).await.unwrap(), 4);

        let send = reader.reserve_send(8, 8).unwrap();
        assert_eq!(send.offset, 0);
        assert_eq!(send.len, 4);
        assert_eq!(reader.read_range(send.offset, send.len), b"abcd");

        reader.ack_to(4);
        assert_eq!(poll_fn(|cx| writer.poll_write(cx, b"ef")).await.unwrap(), 2);
        let send = reader.reserve_send(8, 8).unwrap();
        assert_eq!(reader.read_range(send.offset, send.len), b"ef");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pipe_blocks_until_ack() {
        let (mut reader, mut writer) = pipe(4);
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

        reader.ack_to(4);
        yield_now().await;
        assert_eq!(poll_fn(|cx| writer.poll_write(cx, b"e")).await.unwrap(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pipe_closed_waits_for_reader_close() {
        let (mut reader, mut writer) = pipe(8);
        writer.finish();

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
        let (mut reader, mut writer) = pipe(8);
        assert_eq!(poll_fn(|cx| writer.poll_write(cx, b"abcdef")).await.unwrap(), 6);
        let send = reader.reserve_send(8, 6).unwrap();
        assert_eq!(reader.read_range(send.offset, send.len), b"abcdef");
        reader.ack_to(6);

        assert_eq!(poll_fn(|cx| writer.poll_write(cx, b"ghijkl")).await.unwrap(), 6);
        let send = reader.reserve_send(12, 6).unwrap();
        assert_eq!(reader.read_range(send.offset, send.len), b"ghijkl");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn closing_reader_wakes_writer() {
        let (_reader, mut writer) = pipe(4);
        let mut reader = _reader;
        assert_eq!(poll_fn(|cx| writer.poll_write(cx, b"abcd")).await.unwrap(), 4);
        reader.close();
        let err = poll_fn(|cx| writer.poll_write(cx, b"e")).await.unwrap_err();
        assert_eq!(err, PipeClosed);
    }
}
