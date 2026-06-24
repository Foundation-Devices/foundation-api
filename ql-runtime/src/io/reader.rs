use std::{
    future::poll_fn,
    task::{Context, Poll},
};

use bytes::Bytes;
use ql_wire::{ResetCode, ResetTarget, StreamId};

use super::{
    inner::{Item, RxInner},
    slot::PopError,
    Rx,
};
use crate::{command::Command, log, QlStreamError};

pub struct StreamReader {
    rx: Rx,
    target: ResetTarget,
    terminal: ReaderTerminalState,
    runtime_tx: async_channel::Sender<Command>,
}

enum ReaderTerminalState {
    Open,
    Delivered,
}

unsafe impl Sync for StreamReader {}

impl std::fmt::Debug for StreamReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamReader")
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
    pub(crate) fn new(
        shared: Rx,
        target: ResetTarget,
        runtime_tx: async_channel::Sender<Command>,
    ) -> Self {
        Self {
            rx: shared,
            target,
            terminal: ReaderTerminalState::Open,
            runtime_tx,
        }
    }

    pub fn stream_id(&self) -> StreamId {
        self.rx.stream_id()
    }

    pub fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, QlStreamError>> {
        if matches!(self.terminal, ReaderTerminalState::Delivered) {
            return Poll::Ready(Ok(None));
        }

        match self.try_read_ready() {
            Poll::Ready(result) => return Poll::Ready(result),
            Poll::Pending => {}
        }

        self.rx.register_waiter(cx.waker());

        match self.try_read_ready() {
            Poll::Ready(result) => {
                self.rx.unregister_waiter();
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn try_read_ready(&mut self) -> Poll<Result<Option<Bytes>, QlStreamError>> {
        match self.rx.pop() {
            Ok(Item::Chunk(bytes)) => {
                log::trace!(
                    "byte reader received chunk: stream_id={} target={:?} len={}",
                    self.rx.stream_id(),
                    self.target,
                    bytes.len()
                );
                let _ = self.runtime_tx.try_send(Command::PollInbound {
                    stream_id: self.rx.stream_id(),
                });
                Poll::Ready(Ok(Some(bytes)))
            }
            Ok(Item::Error(error)) => {
                log::debug!(
                    "byte reader delivered terminal error: stream_id={} target={:?} error={:?}",
                    self.rx.stream_id(),
                    self.target,
                    error
                );
                self.terminal = ReaderTerminalState::Delivered;
                Poll::Ready(Err(error))
            }
            Err(PopError) => {
                if RxInner::is_finished(self.rx.load_state()) {
                    log::debug!(
                        "byte reader delivered clean eof: stream_id={} target={:?}",
                        self.rx.stream_id(),
                        self.target
                    );
                    self.terminal = ReaderTerminalState::Delivered;
                    return Poll::Ready(Ok(None));
                }
                Poll::Pending
            }
        }
    }

    pub async fn read(&mut self) -> Result<Option<Bytes>, QlStreamError> {
        poll_fn(|cx| self.poll_read(cx)).await
    }

    pub fn reset(mut self, code: ResetCode) {
        self.reset_inner(code);
    }

    fn reset_inner(&mut self, code: ResetCode) {
        if matches!(self.terminal, ReaderTerminalState::Delivered) {
            return;
        }
        log::debug!(
            "byte reader explicit reset: stream_id={:?} target={:?} code={:?}",
            self.rx.stream_id(),
            self.target,
            code
        );
        self.terminal = ReaderTerminalState::Delivered;
        let _ = self.runtime_tx.try_send(Command::ResetStream {
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
            "byte reader drop reset: stream_id={:?} target={:?} code={:?}",
            self.rx.stream_id(),
            self.target,
            ResetCode::DROPPED
        );
        let _ = self.runtime_tx.try_send(Command::ResetStream {
            stream_id: self.rx.stream_id(),
            target: self.target,
            code: ResetCode::DROPPED,
        });
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    use std::task::{Context, Poll, Waker};

    use bytes::Bytes;
    use loom::thread;
    use ql_wire::ResetTarget;

    use super::*;
    use crate::io::sync::loom::*;

    #[test]
    fn poll_read_observes_chunk_racing_with_registration() {
        check_model(|| {
            let inner = shared();
            let mut reader = StreamReader::new(Rx(inner.clone()), ResetTarget::Origin, handle());
            let mut cx = Context::from_waker(Waker::noop());

            let producer = {
                let inner = inner.clone();
                thread::spawn(move || {
                    inner.rx.try_write(Bytes::from_static(b"abc")).unwrap();
                })
            };

            let first = reader.poll_read(&mut cx);
            producer.join().unwrap();

            match first {
                Poll::Ready(Ok(Some(bytes))) => {
                    assert_eq!(bytes, Bytes::from_static(b"abc"));
                }
                Poll::Pending => {
                    assert_eq!(
                        reader.poll_read(&mut cx),
                        Poll::Ready(Ok(Some(Bytes::from_static(b"abc"))))
                    );
                }
                other => panic!("unexpected first poll result: {other:?}"),
            }
        });
    }
}
