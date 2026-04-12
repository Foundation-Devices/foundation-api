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
    command::RuntimeCommand,
    QlStreamError, RuntimeHandle,
};

pub struct ByteWriter {
    stream_id: StreamId,
    target: CloseTarget,
    writer: Option<ChunkSlotTx>,
    listener: Option<EventListener>,
    terminal: WriteTerminalState,
    handle: RuntimeHandle,
}

enum WriteTerminalState {
    Armed(oneshot::Receiver<QlStreamError>),
    Terminal(QlStreamError),
}

impl std::fmt::Debug for ByteWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundByteStream")
            .field("stream_id", &self.stream_id)
            .field("target", &self.target)
            .field("closed", &self.writer.is_none())
            .finish_non_exhaustive()
    }
}

impl ByteWriter {
    pub(crate) fn new(
        stream_id: StreamId,
        target: CloseTarget,
        writer: ChunkSlotTx,
        terminal: oneshot::Receiver<QlStreamError>,
        handle: RuntimeHandle,
    ) -> Self {
        Self {
            stream_id,
            target,
            writer: Some(writer),
            listener: None,
            terminal: WriteTerminalState::Armed(terminal),
            handle,
        }
    }

    fn poll_runtime(&self) {
        self.handle.send(RuntimeCommand::PollStream {
            stream_id: self.stream_id,
        });
    }

    pub fn poll_write(
        &mut self,
        bytes: &mut Bytes,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), QlStreamError>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let Some(writer) = self.writer.as_ref() else {
            return self.poll_terminal_error(cx).map(Err);
        };

        match writer.poll_send(bytes, &mut self.listener, cx) {
            Poll::Ready(Ok(())) => {
                self.listener = None;
                self.poll_runtime();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(SendClosed(_bytes))) => {
                self.writer.take();
                self.listener = None;
                self.poll_terminal_error(cx).map(Err)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    pub async fn write(&mut self, bytes: Bytes) -> Result<(), QlStreamError> {
        let mut bytes = bytes;
        poll_fn(|cx| self.poll_write(&mut bytes, cx)).await
    }

    pub fn finish(mut self) {
        let Some(writer) = self.writer.take() else {
            return;
        };
        writer.close();
        self.poll_runtime();
    }

    pub fn close(mut self, code: StreamCloseCode) {
        self.close_inner(code);
    }
}

impl Drop for ByteWriter {
    fn drop(&mut self) {
        self.close_inner(StreamCloseCode::CANCELLED);
    }
}

impl ByteWriter {
    fn poll_terminal_error(&mut self, cx: &mut Context<'_>) -> Poll<QlStreamError> {
        match &mut self.terminal {
            WriteTerminalState::Terminal(error) => Poll::Ready(error.clone()),
            WriteTerminalState::Armed(receiver) => match Pin::new(receiver).poll(cx) {
                Poll::Ready(Ok(error)) => {
                    self.terminal = WriteTerminalState::Terminal(error.clone());
                    Poll::Ready(error)
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
        self.listener = None;
        self.handle.send(RuntimeCommand::CloseStream {
            stream_id: self.stream_id,
            target: self.target,
            code,
        });
    }
}
