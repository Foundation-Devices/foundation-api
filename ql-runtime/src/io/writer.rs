use std::{
    future::{poll_fn, Future},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use ql_common::ResetCode;
use ql_fsm::StreamResetTarget;

use super::{
    inner::{Item, TxInner},
    slot::PopError,
    PushError, Tx,
};
use crate::{command::Command, log, QlStreamError, ResetOrigin};

pub struct StreamWriter {
    tx: Tx,
    open: bool,
    terminal: WriterTerminalState,
    runtime_tx: async_channel::Sender<Command>,
}

pub struct StreamWriterFinish {
    writer: StreamWriter,
}

enum WriterTerminalState {
    Pending,
    Terminal(Result<(), QlStreamError>),
}

unsafe impl Sync for StreamWriter {}

impl std::fmt::Debug for StreamWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamWriter")
            .field("stream_id", &self.tx.stream_id())
            .field("closed", &!self.open)
            .finish_non_exhaustive()
    }
}

impl StreamWriter {
    pub(crate) fn new(shared: Tx, runtime_tx: async_channel::Sender<Command>) -> Self {
        Self {
            tx: shared,
            open: true,
            terminal: WriterTerminalState::Pending,
            runtime_tx,
        }
    }

    pub fn poll_write(
        &mut self,
        bytes: &mut Bytes,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), QlStreamError>> {
        if !self.open {
            return self.poll_terminal(cx);
        }

        if bytes.is_empty() {
            return Poll::Ready(Ok(()));
        }

        match self.tx.try_write(std::mem::take(bytes)) {
            Ok(()) => {
                log::trace!(
                    "byte writer accepted chunk: stream_id={}",
                    self.tx.stream_id()
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
                    "byte writer accepted chunk: stream_id={}",
                    self.tx.stream_id()
                );
                self.poll_runtime();
                Poll::Ready(Ok(()))
            }
            Err(PushError::Closed(chunk)) => {
                self.tx.unregister_waiter();
                *bytes = chunk;
                self.open = false;
                self.poll_terminal(cx)
            }
            Err(PushError::Full(chunk)) => {
                *bytes = chunk;
                Poll::Pending
            }
        }
    }

    pub async fn write(&mut self, bytes: Bytes) -> Result<(), QlStreamError> {
        let mut bytes = bytes;
        poll_fn(|cx| self.poll_write(&mut bytes, cx)).await
    }

    pub fn finish(mut self) -> StreamWriterFinish {
        self.queue_finish();
        StreamWriterFinish { writer: self }
    }

    pub fn reset(&mut self, code: ResetCode) {
        if !self.open {
            return;
        }
        self.open = false;
        self.terminal = WriterTerminalState::Terminal(Err(QlStreamError::StreamReset {
            code,
            origin: ResetOrigin::Local,
        }));
        log::debug!(
            "byte writer reset: stream_id={:?} code={:?}",
            self.tx.stream_id(),
            code
        );
        let _ = self.runtime_tx.try_send(Command::ResetStream {
            stream_id: self.tx.stream_id(),
            target: StreamResetTarget::Writer,
            code,
        });
    }

    fn queue_finish(&mut self) {
        if !self.open {
            return;
        }
        log::debug!("byte writer finish: stream_id={}", self.tx.stream_id());
        self.open = false;
        self.tx.request_finish();
        self.poll_runtime();
    }

    fn poll_runtime(&self) {
        let _ = self.runtime_tx.try_send(Command::PollStream {
            stream_id: self.tx.stream_id(),
        });
    }

    fn poll_terminal(&mut self, cx: &Context<'_>) -> Poll<Result<(), QlStreamError>> {
        match &self.terminal {
            WriterTerminalState::Terminal(result) => return Poll::Ready(result.clone()),
            WriterTerminalState::Pending => {}
        }

        match self.try_poll_terminal_ready() {
            Poll::Ready(result) => return Poll::Ready(result),
            Poll::Pending => {}
        }

        self.tx.register_waiter(cx.waker());

        match self.try_poll_terminal_ready() {
            Poll::Ready(result) => {
                self.tx.unregister_waiter();
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
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
                Err(PopError) => {}
            }
        }

        Poll::Pending
    }
}

impl Future for StreamWriterFinish {
    type Output = Result<(), QlStreamError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.writer.poll_terminal(cx)
    }
}

impl Drop for StreamWriter {
    fn drop(&mut self) {
        self.reset(ResetCode::DROPPED);
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    use std::task::{Context, Poll, Waker};

    use bytes::Bytes;
    use loom::thread;

    use super::*;
    use crate::io::sync::loom::*;

    #[test]
    fn poll_write_observes_capacity_racing_with_registration() {
        check_model(|| {
            let inner = shared();
            inner.tx.try_write(Bytes::from_static(b"abc")).unwrap();

            let mut writer = StreamWriter::new(Tx(inner.clone()), handle());
            let mut bytes = Bytes::from_static(b"xyz");
            let mut cx = Context::from_waker(Waker::noop());

            let drainer = {
                let inner = inner.clone();
                thread::spawn(move || {
                    assert!(matches!(inner.tx.pop(), Ok(Item::Chunk(_))));
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
            let writer = StreamWriter::new(Tx(inner.clone()), handle());
            let mut cx = Context::from_waker(Waker::noop());
            let mut finish = writer.finish();

            let finisher = {
                let inner = inner.clone();
                thread::spawn(move || {
                    inner.tx.finish();
                })
            };

            let first = Pin::new(&mut finish).poll(&mut cx);
            finisher.join().unwrap();

            match first {
                Poll::Ready(Ok(())) => {}
                Poll::Pending => {
                    assert_eq!(Pin::new(&mut finish).poll(&mut cx), Poll::Ready(Ok(())));
                }
                other => panic!("unexpected first poll result: {other:?}"),
            }
        });
    }
}
