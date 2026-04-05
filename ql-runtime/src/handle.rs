use std::{pin::Pin, task::Poll};

use async_channel::{Receiver, Sender};
use futures_lite::{future::poll_fn, Stream};

use crate::{
    command::RuntimeCommand, CloseCode, CloseTarget, InboundEvent, OpenedStreamDelivery, Peer,
    QlError, StreamId,
};

#[derive(Clone)]
pub struct RuntimeHandle {
    pub(crate) tx: Sender<RuntimeCommand>,
    pub(crate) stream_send_buffer_bytes: usize,
}

#[derive(Debug)]
pub struct OutboundStream {
    pub stream_id: StreamId,
    pub request: ByteWriter,
    pub response: ByteReader,
}

#[derive(Debug)]
pub struct InboundStream {
    pub stream_id: StreamId,
    pub request: ByteReader,
    pub response: ByteWriter,
}

pub struct ByteReader {
    stream_id: StreamId,
    target: CloseTarget,
    rx: Receiver<InboundEvent>,
    tx: Sender<RuntimeCommand>,
    finished: bool,
}

impl std::fmt::Debug for ByteReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundByteStream")
            .field("stream_id", &self.stream_id)
            .field("target", &self.target)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

pub struct ByteWriter {
    stream_id: StreamId,
    target: CloseTarget,
    writer: Option<piper::Writer>,
    tx: Sender<RuntimeCommand>,
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

impl ByteReader {
    pub(crate) fn new(
        stream_id: StreamId,
        target: CloseTarget,
        rx: Receiver<InboundEvent>,
        tx: Sender<RuntimeCommand>,
    ) -> Self {
        Self {
            stream_id,
            target,
            rx,
            tx,
            finished: false,
        }
    }

    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, QlError> {
        poll_fn(|cx| self.poll_next_chunk(cx)).await
    }

    pub fn poll_next_chunk(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<Option<Vec<u8>>, QlError>> {
        if self.finished {
            return Poll::Ready(Ok(None));
        }

        // `async_channel::Receiver` implements `Stream` and stores its listener state
        // internally, so poll it directly rather than recreating a `recv()` future.
        // SAFETY: `self.rx` is pinned for the duration of this call and is not moved
        // before `poll_next` returns.
        let mut rx = unsafe { Pin::new_unchecked(&mut self.rx) };
        match Stream::poll_next(rx.as_mut(), cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(InboundEvent::Data(bytes))) => Poll::Ready(Ok(Some(bytes))),
            Poll::Ready(Some(InboundEvent::Finished)) => {
                self.finished = true;
                Poll::Ready(Ok(None))
            }
            Poll::Ready(Some(InboundEvent::Failed(error))) => {
                self.finished = true;
                Poll::Ready(Err(error))
            }
            Poll::Ready(None) => {
                self.finished = true;
                Poll::Ready(Err(QlError::Cancelled))
            }
        }
    }

    pub async fn close(mut self, code: CloseCode, payload: Vec<u8>) -> Result<(), QlError> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        self.tx
            .send(RuntimeCommand::CloseStream {
                stream_id: self.stream_id,
                target: self.target,
                code,
                payload,
            })
            .await
            .map_err(|_| QlError::Cancelled)
    }
}

impl Drop for ByteReader {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = self.tx.try_send(RuntimeCommand::CloseStream {
            stream_id: self.stream_id,
            target: self.target,
            code: CloseCode::CANCELLED,
            payload: Vec::new(),
        });
    }
}

impl ByteWriter {
    pub(crate) fn new(
        stream_id: StreamId,
        target: CloseTarget,
        writer: piper::Writer,
        tx: Sender<RuntimeCommand>,
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

    pub async fn close(mut self, code: CloseCode, payload: Vec<u8>) -> Result<(), QlError> {
        if self.writer.take().is_none() {
            return Ok(());
        }
        self.tx
            .send(RuntimeCommand::CloseStream {
                stream_id: self.stream_id,
                target: self.target,
                code,
                payload,
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
            code: CloseCode::CANCELLED,
            payload: Vec::new(),
        });
    }
}

impl RuntimeHandle {
    pub fn bind_peer(&self, peer: Peer) {
        self.send(RuntimeCommand::BindPeer { peer })
    }

    pub fn pair(&self) -> Result<(), QlError> {
        self.tx
            .send_blocking(RuntimeCommand::Pair)
            .map_err(|_| QlError::Cancelled)
    }

    pub fn connect(&self) -> Result<(), QlError> {
        self.tx
            .send_blocking(RuntimeCommand::Connect)
            .map_err(|_| QlError::Cancelled)
    }

    pub fn unpair(&self) -> Result<(), QlError> {
        self.tx
            .send_blocking(RuntimeCommand::Unpair)
            .map_err(|_| QlError::Cancelled)
    }

    pub fn send_incoming(&self, bytes: Vec<u8>) {
        self.send(RuntimeCommand::Incoming(bytes))
    }

    pub async fn open_stream(&self) -> Result<OutboundStream, QlError> {
        let (request_reader, request_writer) = piper::pipe(self.stream_send_buffer_bytes);
        let (start_tx, start_rx) = oneshot::channel();

        self.tx
            .send(RuntimeCommand::OpenStream {
                request_reader,
                start: start_tx,
            })
            .await
            .map_err(|_| QlError::Cancelled)?;

        let OpenedStreamDelivery {
            stream_id,
            response,
        } = start_rx.await.unwrap_or(Err(QlError::Cancelled))?;

        Ok(OutboundStream {
            stream_id,
            request: ByteWriter::new(
                stream_id,
                CloseTarget::Origin,
                request_writer,
                self.tx.clone(),
            ),
            response: ByteReader::new(stream_id, CloseTarget::Return, response, self.tx.clone()),
        })
    }

    #[cfg(feature = "rpc")]
    pub fn rpc(&self) -> crate::rpc::RpcHandle {
        crate::rpc::RpcHandle {
            inner: self.clone(),
        }
    }
}

impl RuntimeHandle {
    #[inline]
    #[track_caller]
    fn send(&self, cmd: RuntimeCommand) {
        self.tx.send_blocking(cmd).expect("runtime is alive")
    }
}
