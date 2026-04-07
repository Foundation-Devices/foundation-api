use std::{
    future::{poll_fn, Future},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use event_listener::EventListener;
use ql_wire::{CloseTarget, StreamCloseCode, StreamId};

use crate::{chunk_slot::ChunkSlotRx, command::RuntimeCommand, QlError, RuntimeHandle};

pub struct ByteReader {
    stream_id: StreamId,
    target: CloseTarget,
    reader: Option<ChunkSlotRx>,
    listener: Option<EventListener>,
    terminal: TerminalState,
    handle: RuntimeHandle,
}

enum TerminalState {
    Armed(oneshot::Receiver<Result<(), QlError>>),
    Terminal(Result<(), QlError>),
    Delivered,
}

impl std::fmt::Debug for ByteReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundByteStream")
            .field("stream_id", &self.stream_id)
            .field("target", &self.target)
            .field(
                "terminal",
                &matches!(self.terminal, TerminalState::Delivered),
            )
            .finish_non_exhaustive()
    }
}

impl ByteReader {
    pub(crate) fn new(
        stream_id: StreamId,
        target: CloseTarget,
        reader: ChunkSlotRx,
        terminal: oneshot::Receiver<Result<(), QlError>>,
        handle: RuntimeHandle,
    ) -> Self {
        Self {
            stream_id,
            target,
            reader: Some(reader),
            listener: None,
            terminal: TerminalState::Armed(terminal),
            handle,
        }
    }

    pub fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, QlError>> {
        if matches!(self.terminal, TerminalState::Delivered) {
            return Poll::Ready(Ok(None));
        }

        if let Some(reader) = self.reader.as_ref() {
            match reader.poll_recv(usize::MAX, &mut self.listener, cx) {
                Poll::Ready(Ok(bytes)) => {
                    self.handle.send(RuntimeCommand::PollInbound {
                        stream_id: self.stream_id,
                    });
                    return Poll::Ready(Ok(Some(bytes)));
                }
                Poll::Ready(Err(_)) => {
                    self.reader = None;
                    self.listener = None;
                }
                Poll::Pending => {}
            }
        }

        if let TerminalState::Armed(terminal) = &mut self.terminal {
            let result = match Pin::new(terminal).poll(cx) {
                Poll::Pending => None,
                Poll::Ready(Ok(result)) => Some(result),
                Poll::Ready(Err(_)) => Some(Err(QlError::Cancelled)),
            };
            if let Some(result) = result {
                self.terminal = TerminalState::Terminal(result);
            }
        }

        match &self.terminal {
            TerminalState::Armed(_) => Poll::Pending,
            TerminalState::Terminal(Ok(())) => {
                self.terminal = TerminalState::Delivered;
                Poll::Ready(Ok(None))
            }
            TerminalState::Terminal(Err(error)) => {
                let error = error.clone();
                self.terminal = TerminalState::Delivered;
                Poll::Ready(Err(error))
            }
            TerminalState::Delivered => Poll::Ready(Ok(None)),
        }
    }

    pub async fn read_chunk(&mut self) -> Result<Option<Bytes>, QlError> {
        poll_fn(|cx| self.poll_read_chunk(cx)).await
    }

    pub fn close(mut self, code: StreamCloseCode) {
        if matches!(self.terminal, TerminalState::Delivered) {
            return;
        }
        self.reader.take();
        self.listener = None;
        self.terminal = TerminalState::Delivered;
        self.handle.send(RuntimeCommand::CloseStream {
            stream_id: self.stream_id,
            target: self.target,
            code,
        });
    }
}

impl Drop for ByteReader {
    fn drop(&mut self) {
        if matches!(self.terminal, TerminalState::Delivered) {
            return;
        }
        self.handle.send(RuntimeCommand::CloseStream {
            stream_id: self.stream_id,
            target: self.target,
            code: StreamCloseCode(0),
        });
    }
}
