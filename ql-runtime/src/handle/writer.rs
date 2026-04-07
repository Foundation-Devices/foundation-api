use bytes::Bytes;
use ql_wire::{CloseTarget, StreamCloseCode, StreamId};

use crate::{chunk_slot::ChunkSlotTx, command::RuntimeCommand, QlStreamError, RuntimeHandle};

pub struct ByteWriter {
    stream_id: StreamId,
    target: CloseTarget,
    writer: Option<ChunkSlotTx>,
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
            terminal: WriteTerminalState::Armed(terminal),
            handle,
        }
    }

    fn poll_runtime(&self) {
        self.handle.send(RuntimeCommand::PollStream {
            stream_id: self.stream_id,
        });
    }

    pub async fn write(&mut self, bytes: Bytes) -> Result<(), QlStreamError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let Some(writer) = self.writer.as_ref() else {
            return Err(self.terminal_error().await);
        };
        if writer.send(bytes).await.is_err() {
            self.writer.take();
            return Err(self.terminal_error().await);
        }
        self.poll_runtime();
        Ok(())
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
        self.close_inner(StreamCloseCode(0));
    }
}

impl ByteWriter {
    async fn terminal_error(&mut self) -> QlStreamError {
        match &mut self.terminal {
            WriteTerminalState::Terminal(error) => error.clone(),
            WriteTerminalState::Armed(receiver) => {
                let error = receiver
                    .await
                    .expect("byte writer terminal dropped before sending a terminal state");
                self.terminal = WriteTerminalState::Terminal(error.clone());
                error
            }
        }
    }

    fn close_inner(&mut self, code: StreamCloseCode) {
        if self.writer.take().is_none() {
            return;
        }
        self.handle.send(RuntimeCommand::CloseStream {
            stream_id: self.stream_id,
            target: self.target,
            code,
        });
    }
}
