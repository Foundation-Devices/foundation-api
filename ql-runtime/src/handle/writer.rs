use std::{
    future::{poll_fn, Future},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use event_listener::EventListener;
use ql_wire::{CloseTarget, StreamCloseCode, StreamId};

use crate::{
    chunk_slot::{ChunkSlotTx, SendClosed},
    command::Command,
    log, QlStreamError, RuntimeHandle,
};

pub struct StreamWriter {
    stream_id: StreamId,
    target: CloseTarget,
    writer: Option<ChunkSlotTx>,
    wait: Option<EventListener>,
    terminal: WriteTerminalState,
    handle: RuntimeHandle,
}

enum WriteTerminalState {
    Armed(oneshot::Receiver<Result<(), QlStreamError>>),
    Terminal(Result<(), QlStreamError>),
}

// Safety: `ByteWriter` contains a `oneshot::Receiver`, which is `!Sync`, but that receiver is
// fully encapsulated. No safe API accesses it through `&self`; all access requires `&mut self`
// or ownership, so shared references cannot race the receiver state across threads.
unsafe impl Sync for StreamWriter {}

impl std::fmt::Debug for StreamWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundByteStream")
            .field("stream_id", &self.stream_id)
            .field("target", &self.target)
            .field("closed", &self.writer.is_none())
            .finish_non_exhaustive()
    }
}

impl StreamWriter {
    pub fn poll_write(
        &mut self,
        bytes: &mut Bytes,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), QlStreamError>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let Some(writer) = self.writer.as_ref() else {
            return self.poll_terminal(cx);
        };

        match writer.poll_send(bytes, &mut self.wait, cx) {
            Poll::Ready(Ok(())) => {
                log::trace!(
                    "byte writer accepted chunk: stream_id={:?} target={:?}",
                    self.stream_id,
                    self.target
                );
                self.wait = None;
                self.poll_runtime();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(SendClosed(_bytes))) => {
                log::debug!(
                    "byte writer send closed: stream_id={:?} target={:?}",
                    self.stream_id,
                    self.target
                );
                self.writer.take();
                self.wait = None;
                self.poll_terminal(cx)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    pub async fn write(&mut self, bytes: Bytes) -> Result<(), QlStreamError> {
        let mut bytes = bytes;
        poll_fn(|cx| self.poll_write(&mut bytes, cx)).await
    }

    pub fn queue_finish(&mut self) {
        let Some(writer) = self.writer.take() else {
            return;
        };
        log::debug!(
            "byte writer finish: stream_id={:?} target={:?}",
            self.stream_id,
            self.target
        );
        writer.close();
        self.wait = None;
        self.poll_runtime();
    }

    pub async fn finish(mut self) -> Result<(), QlStreamError> {
        self.queue_finish();
        poll_fn(|cx| self.poll_terminal(cx)).await
    }

    pub fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), QlStreamError>> {
        if self.writer.is_some() {
            self.queue_finish();
        }
        self.poll_terminal(cx)
    }

    pub fn close(mut self, code: StreamCloseCode) {
        self.close_inner(code);
    }
}

impl Drop for StreamWriter {
    fn drop(&mut self) {
        self.close_inner(StreamCloseCode::CANCELLED);
    }
}

impl StreamWriter {
    pub(crate) fn new(
        stream_id: StreamId,
        target: CloseTarget,
        writer: ChunkSlotTx,
        terminal: oneshot::Receiver<Result<(), QlStreamError>>,
        handle: RuntimeHandle,
    ) -> Self {
        Self {
            stream_id,
            target,
            writer: Some(writer),
            wait: None,
            terminal: WriteTerminalState::Armed(terminal),
            handle,
        }
    }

    fn poll_runtime(&self) {
        self.handle.try_send(Command::PollStream {
            stream_id: self.stream_id,
        });
    }

    fn poll_terminal(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), QlStreamError>> {
        match &mut self.terminal {
            WriteTerminalState::Terminal(result) => Poll::Ready(result.clone()),
            WriteTerminalState::Armed(receiver) => match Pin::new(receiver).poll(cx) {
                Poll::Ready(Ok(result)) => {
                    self.terminal = WriteTerminalState::Terminal(result.clone());
                    Poll::Ready(result)
                }
                Poll::Ready(Err(_)) => {
                    panic!("byte writer terminal dropped before sending a terminal state")
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn close_inner(&mut self, code: StreamCloseCode) {
        if self.writer.take().is_none() {
            return;
        }
        log::debug!(
            "byte writer close: stream_id={:?} target={:?} code={:?}",
            self.stream_id,
            self.target,
            code
        );
        self.wait = None;
        self.handle.try_send(Command::CloseStream {
            stream_id: self.stream_id,
            target: self.target,
            code,
        });
    }
}
