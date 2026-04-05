use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use ql_wire::{CloseTarget, StreamCloseCode, StreamId};

use crate::{command::RuntimeCommand, QlError};

pub struct ByteReader {
    stream_id: StreamId,
    target: CloseTarget,
    reader: piper::Reader,
    terminal: TerminalState,
    tx: async_channel::Sender<RuntimeCommand>,
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
        reader: piper::Reader,
        terminal: oneshot::Receiver<Result<(), QlError>>,
        tx: async_channel::Sender<RuntimeCommand>,
    ) -> Self {
        Self {
            stream_id,
            target,
            reader,
            terminal: TerminalState::Armed(terminal),
            tx,
        }
    }

    pub fn poll_fill_buf(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<&[u8]>, QlError>> {
        if matches!(self.terminal, TerminalState::Delivered) {
            return Poll::Ready(Ok(None));
        }

        if self.reader.poll(cx) == Poll::Ready(true) {
            return Poll::Ready(Ok(Some(self.reader.peek_buf())));
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

    pub fn consume(&mut self, amt: usize) {
        if amt == 0 {
            return;
        }
        self.reader.consume(amt);
        let _ = self.tx.try_send(RuntimeCommand::PollInbound {
            stream_id: self.stream_id,
        });
    }

    pub async fn close(mut self, code: StreamCloseCode) -> Result<(), QlError> {
        if matches!(self.terminal, TerminalState::Delivered) {
            return Ok(());
        }
        self.terminal = TerminalState::Delivered;
        self.tx
            .send(RuntimeCommand::CloseStream {
                stream_id: self.stream_id,
                target: self.target,
                code,
            })
            .await
            .map_err(|_| QlError::Cancelled)
    }
}

impl Drop for ByteReader {
    fn drop(&mut self) {
        if matches!(self.terminal, TerminalState::Delivered) {
            return;
        }
        let _ = self.tx.try_send(RuntimeCommand::CloseStream {
            stream_id: self.stream_id,
            target: self.target,
            code: StreamCloseCode(0),
        });
    }
}
