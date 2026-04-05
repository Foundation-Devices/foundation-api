use futures_lite::future::poll_fn;
use ql_wire::{CloseTarget, StreamCloseCode, StreamId};

use crate::{command::RuntimeCommand, QlError};

pub struct ByteWriter {
    stream_id: StreamId,
    target: CloseTarget,
    writer: Option<piper::Writer>,
    tx: async_channel::Sender<RuntimeCommand>,
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
        writer: piper::Writer,
        tx: async_channel::Sender<RuntimeCommand>,
    ) -> Self {
        Self {
            stream_id,
            target,
            writer: Some(writer),
            tx,
        }
    }

    fn poll_runtime(&self) -> Result<(), QlError> {
        self.tx
            .try_send(RuntimeCommand::PollStream {
                stream_id: self.stream_id,
            })
            .map_err(|_| QlError::Cancelled)
    }

    pub async fn write(&mut self, bytes: &[u8]) -> Result<usize, QlError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.poll_runtime()?;
        let writer = self.writer.as_mut().expect("stream not finished or closed");
        let written = poll_fn(|cx| writer.poll_fill_bytes(cx, bytes)).await;
        if written == 0 {
            self.writer.take();
            return Err(QlError::Cancelled);
        }
        self.poll_runtime()?;
        Ok(written)
    }

    pub async fn write_all(&mut self, mut bytes: &[u8]) -> Result<(), QlError> {
        while !bytes.is_empty() {
            let written = self.write(bytes).await?;
            if written == 0 {
                return Err(QlError::Cancelled);
            }
            bytes = &bytes[written..];
        }
        Ok(())
    }

    pub async fn finish(mut self) -> Result<(), QlError> {
        if self.writer.take().is_none() {
            return Ok(());
        }
        self.poll_runtime()
    }

    pub async fn close(mut self, code: StreamCloseCode) -> Result<(), QlError> {
        if self.writer.take().is_none() {
            return Ok(());
        }
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

impl Drop for ByteWriter {
    fn drop(&mut self) {
        if self.writer.take().is_none() {
            return;
        }
        let _ = self.tx.try_send(RuntimeCommand::CloseStream {
            stream_id: self.stream_id,
            target: self.target,
            code: StreamCloseCode(0),
        });
    }
}
