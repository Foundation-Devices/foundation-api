use std::{
    future::poll_fn,
    task::{Context, Poll},
};

use bytes::Bytes;
use ql_wire::{CloseTarget, StreamCloseCode};

use super::{
    queue::PopError,
    shared::{Item, RxInner},
    Rx,
};
use crate::{command::Command, log, QlStreamError, RuntimeHandle};

pub struct StreamReader {
    rx: Rx,
    target: CloseTarget,
    pending: Bytes,
    terminal: ReaderTerminalState,
    handle: RuntimeHandle,
}

enum ReaderTerminalState {
    Open,
    Delivered,
}

unsafe impl Sync for StreamReader {}

impl std::fmt::Debug for StreamReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundByteStream")
            .field("stream_id", &self.rx.stream_id())
            .field("target", &self.target)
            .field(
                "terminal",
                &matches!(self.terminal, ReaderTerminalState::Delivered),
            )
            .finish_non_exhaustive()
    }
}

impl StreamReader {
    pub(crate) fn new(shared: Rx, target: CloseTarget, handle: RuntimeHandle) -> Self {
        Self {
            rx: shared,
            target,
            pending: Bytes::new(),
            terminal: ReaderTerminalState::Open,
            handle,
        }
    }

    pub fn poll_read(
        &mut self,
        max_len: usize,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, QlStreamError>> {
        if matches!(self.terminal, ReaderTerminalState::Delivered) {
            return Poll::Ready(Ok(None));
        }

        loop {
            match self.try_read_ready(max_len) {
                Poll::Ready(result) => return Poll::Ready(result),
                Poll::Pending => {}
            }

            self.rx.register_waiter(cx.waker());

            match self.try_read_ready(max_len) {
                Poll::Ready(result) => {
                    self.rx.unregister_waiter();
                    return Poll::Ready(result);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn try_read_ready(&mut self, max_len: usize) -> Poll<Result<Option<Bytes>, QlStreamError>> {
        if !self.pending.is_empty() {
            let pending = &mut self.pending;
            let bytes = if pending.len() <= max_len {
                std::mem::take(pending)
            } else {
                pending.split_to(max_len)
            };
            self.handle.try_send(Command::PollInbound {
                stream_id: self.rx.stream_id(),
            });
            return Poll::Ready(Ok(Some(bytes)));
        }

        match self.rx.pop() {
            Ok(Item::Chunk(mut bytes)) => {
                log::trace!(
                    "byte reader received chunk: stream_id={:?} target={:?} len={}",
                    self.rx.stream_id(),
                    self.target,
                    bytes.len()
                );
                self.handle.try_send(Command::PollInbound {
                    stream_id: self.rx.stream_id(),
                });
                if bytes.len() <= max_len {
                    return Poll::Ready(Ok(Some(bytes)));
                }
                let head = bytes.split_to(max_len);
                self.pending = bytes;
                Poll::Ready(Ok(Some(head)))
            }
            Ok(Item::Error(error)) => {
                log::debug!(
                    "byte reader delivered terminal error: stream_id={:?} target={:?} error={:?}",
                    self.rx.stream_id(),
                    self.target,
                    error
                );
                self.terminal = ReaderTerminalState::Delivered;
                Poll::Ready(Err(error))
            }
            Err(PopError::Empty) => {
                if RxInner::is_finished(self.rx.load_state()) {
                    log::debug!(
                        "byte reader delivered clean eof: stream_id={:?} target={:?}",
                        self.rx.stream_id(),
                        self.target
                    );
                    self.terminal = ReaderTerminalState::Delivered;
                    return Poll::Ready(Ok(None));
                }
                Poll::Pending
            }
            Err(PopError::Closed) => panic!("reader endpoint closed unexpectedly"),
        }
    }

    pub fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, QlStreamError>> {
        self.poll_read(usize::MAX, cx)
    }

    pub async fn read(&mut self, max_len: usize) -> Result<Option<Bytes>, QlStreamError> {
        poll_fn(|cx| self.poll_read(max_len, cx)).await
    }

    pub async fn read_chunk(&mut self) -> Result<Option<Bytes>, QlStreamError> {
        self.read(usize::MAX).await
    }

    pub fn close(mut self, code: StreamCloseCode) {
        self.close_inner(code);
    }

    fn close_inner(&mut self, code: StreamCloseCode) {
        if matches!(self.terminal, ReaderTerminalState::Delivered) {
            return;
        }
        log::debug!(
            "byte reader explicit close: stream_id={:?} target={:?} code={:?}",
            self.rx.stream_id(),
            self.target,
            code
        );
        self.terminal = ReaderTerminalState::Delivered;
        self.handle.try_send(Command::CloseStream {
            stream_id: self.rx.stream_id(),
            target: self.target,
            code,
        });
    }
}

impl Drop for StreamReader {
    fn drop(&mut self) {
        if matches!(self.terminal, ReaderTerminalState::Delivered) {
            return;
        }
        log::debug!(
            "byte reader drop close: stream_id={:?} target={:?} code={:?}",
            self.rx.stream_id(),
            self.target,
            StreamCloseCode::CANCELLED
        );
        self.handle.try_send(Command::CloseStream {
            stream_id: self.rx.stream_id(),
            target: self.target,
            code: StreamCloseCode::CANCELLED,
        });
    }
}
