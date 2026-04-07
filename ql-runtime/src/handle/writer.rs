use bytes::Bytes;
use ql_wire::{CloseTarget, StreamCloseCode, StreamId};

use crate::{chunk_slot::ChunkSlotTx, command::RuntimeCommand, QlError};

pub struct ByteWriter {
    stream_id: StreamId,
    target: CloseTarget,
    writer: Option<ChunkSlotTx>,
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
        writer: ChunkSlotTx,
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

    pub async fn write(&mut self, bytes: Bytes) -> Result<(), QlError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let writer = self.writer.as_ref().ok_or(QlError::Cancelled)?;
        self.poll_runtime()?;
        if writer.send(bytes).await.is_err() {
            self.writer.take();
            return Err(QlError::Cancelled);
        }
        self.poll_runtime()?;
        Ok(())
    }

    pub async fn write_all<I>(&mut self, chunks: I) -> Result<(), QlError>
    where
        I: IntoIterator<Item = Bytes>,
    {
        for chunk in chunks {
            self.write(chunk).await?;
        }
        Ok(())
    }

    pub async fn finish(mut self) -> Result<(), QlError> {
        let Some(writer) = self.writer.take() else {
            return Ok(());
        };
        writer.close();
        std::future::ready(self.poll_runtime()).await
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
