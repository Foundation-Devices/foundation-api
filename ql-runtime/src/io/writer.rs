use std::{
    future::poll_fn,
    task::{Context, Poll},
};

use bytes::Bytes;
use ql_wire::{CloseTarget, StreamCloseCode};

use super::{
    inner::{Item, TxInner},
    queue::{PopError, PushError},
    Tx,
};
use crate::{command::Command, log, QlStreamError, RuntimeHandle};

pub struct StreamWriter {
    tx: Tx,
    target: CloseTarget,
    open: bool,
    terminal: WriterTerminalState,
    handle: RuntimeHandle,
}

enum WriterTerminalState {
    Pending,
    Terminal(Result<(), QlStreamError>),
}

unsafe impl Sync for StreamWriter {}

impl std::fmt::Debug for StreamWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundByteStream")
            .field("stream_id", &self.tx.stream_id())
            .field("target", &self.target)
            .field("closed", &!self.open)
            .finish_non_exhaustive()
    }
}

impl StreamWriter {
    pub(crate) fn new(shared: Tx, target: CloseTarget, handle: RuntimeHandle) -> Self {
        Self {
            tx: shared,
            target,
            open: true,
            terminal: WriterTerminalState::Pending,
            handle,
        }
    }

    pub fn poll_write(
        &mut self,
        bytes: &mut Bytes,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), QlStreamError>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(()));
        }

        if !self.open {
            return self.poll_terminal(cx);
        }

        loop {
            match self.tx.try_write(std::mem::take(bytes)) {
                Ok(()) => {
                    log::trace!(
                        "byte writer accepted chunk: stream_id={:?} target={:?}",
                        self.tx.stream_id(),
                        self.target
                    );
                    self.poll_runtime();
                    return Poll::Ready(Ok(()));
                }
                Err(PushError::Closed(chunk)) => {
                    *bytes = chunk;
                    self.open = false;
                    return self.poll_terminal(cx);
                }
                Err(PushError::Full(chunk)) => {
                    *bytes = chunk;
                }
            }

            self.tx.register_waiter(cx.waker());

            match self.tx.try_write(std::mem::take(bytes)) {
                Ok(()) => {
                    self.tx.unregister_waiter();
                    log::trace!(
                        "byte writer accepted chunk: stream_id={:?} target={:?}",
                        self.tx.stream_id(),
                        self.target
                    );
                    self.poll_runtime();
                    return Poll::Ready(Ok(()));
                }
                Err(PushError::Closed(chunk)) => {
                    self.tx.unregister_waiter();
                    *bytes = chunk;
                    self.open = false;
                    return self.poll_terminal(cx);
                }
                Err(PushError::Full(chunk)) => {
                    *bytes = chunk;
                    return Poll::Pending;
                }
            }
        }
    }

    pub async fn write(&mut self, bytes: Bytes) -> Result<(), QlStreamError> {
        let mut bytes = bytes;
        poll_fn(|cx| self.poll_write(&mut bytes, cx)).await
    }

    pub fn queue_finish(&mut self) {
        if !self.open {
            return;
        }
        log::debug!(
            "byte writer finish: stream_id={:?} target={:?}",
            self.tx.stream_id(),
            self.target
        );
        self.open = false;
        self.tx.request_finish();
        self.poll_runtime();
    }

    pub async fn finish(mut self) -> Result<(), QlStreamError> {
        self.queue_finish();
        poll_fn(|cx| self.poll_terminal(cx)).await
    }

    pub fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), QlStreamError>> {
        if self.open {
            self.queue_finish();
        }
        self.poll_terminal(cx)
    }

    pub fn close(mut self, code: StreamCloseCode) {
        self.close_inner(code);
    }

    fn poll_runtime(&self) {
        self.handle.try_send(Command::PollStream {
            stream_id: self.tx.stream_id(),
        });
    }

    fn poll_terminal(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), QlStreamError>> {
        match &self.terminal {
            WriterTerminalState::Terminal(result) => return Poll::Ready(result.clone()),
            WriterTerminalState::Pending => {}
        }

        loop {
            match self.try_poll_terminal_ready() {
                Poll::Ready(result) => return Poll::Ready(result),
                Poll::Pending => {}
            }

            self.tx.register_waiter(cx.waker());

            match self.try_poll_terminal_ready() {
                Poll::Ready(result) => {
                    self.tx.unregister_waiter();
                    return Poll::Ready(result);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn try_poll_terminal_ready(&mut self) -> Poll<Result<(), QlStreamError>> {
        let state = self.tx.load_state();
        if TxInner::terminal_ready(state) {
            if TxInner::terminal_ok(state) {
                self.terminal = WriterTerminalState::Terminal(Ok(()));
                return Poll::Ready(Ok(()));
            }

            match self.tx.pop() {
                Ok(Item::Error(error)) => {
                    self.terminal = WriterTerminalState::Terminal(Err(error.clone()));
                    return Poll::Ready(Err(error));
                }
                Ok(Item::Chunk(_)) => {
                    panic!("writer terminal phase contained chunk data")
                }
                Err(PopError::Empty) => {}
                Err(PopError::Closed) => panic!("writer endpoint closed unexpectedly"),
            }
        }

        Poll::Pending
    }

    fn close_inner(&mut self, code: StreamCloseCode) {
        if !self.open {
            return;
        }
        self.open = false;
        log::debug!(
            "byte writer close: stream_id={:?} target={:?} code={:?}",
            self.tx.stream_id(),
            self.target,
            code
        );
        self.handle.try_send(Command::CloseStream {
            stream_id: self.tx.stream_id(),
            target: self.target,
            code,
        });
    }
}

impl Drop for StreamWriter {
    fn drop(&mut self) {
        self.close_inner(StreamCloseCode::CANCELLED);
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    use std::task::{Context, Poll, Waker};

    use bytes::Bytes;
    use loom::thread;
    use ql_wire::CloseTarget;

    use super::*;
    use crate::io::sync::loom::*;

    #[test]
    fn poll_write_observes_capacity_racing_with_registration() {
        check_model(|| {
            let inner = shared();
            inner.writer.try_write(Bytes::from_static(b"abc")).unwrap();

            let mut writer = StreamWriter::new(
                Tx(inner.clone()),
                CloseTarget::Origin,
                handle(),
            );
            let mut bytes = Bytes::from_static(b"xyz");
            let mut cx = Context::from_waker(Waker::noop());

            let drainer = {
                let inner = inner.clone();
                thread::spawn(move || {
                    assert!(matches!(inner.writer.pop(), Ok(Item::Chunk(_))));
                })
            };

            let first = writer.poll_write(&mut bytes, &mut cx);
            drainer.join().unwrap();

            match first {
                Poll::Ready(Ok(())) => {
                    assert!(bytes.is_empty());
                }
                Poll::Pending => {
                    assert_eq!(writer.poll_write(&mut bytes, &mut cx), Poll::Ready(Ok(())));
                    assert!(bytes.is_empty());
                }
                other => panic!("unexpected first poll result: {other:?}"),
            }
        });
    }

    #[test]
    fn poll_finish_observes_terminal_racing_with_registration() {
        check_model(|| {
            let inner = shared();
            let mut writer = StreamWriter::new(
                Tx(inner.clone()),
                CloseTarget::Origin,
                handle(),
            );
            let mut cx = Context::from_waker(Waker::noop());

            writer.queue_finish();

            let finisher = {
                let inner = inner.clone();
                thread::spawn(move || {
                    inner.writer.finish();
                })
            };

            let first = writer.poll_finish(&mut cx);
            finisher.join().unwrap();

            match first {
                Poll::Ready(Ok(())) => {}
                Poll::Pending => {
                    assert_eq!(writer.poll_finish(&mut cx), Poll::Ready(Ok(())));
                }
                other => panic!("unexpected first poll result: {other:?}"),
            }
        });
    }
}
