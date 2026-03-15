use async_channel::{Receiver, Sender};
use futures_lite::future::poll_fn;

use crate::{
    runtime::{command::RuntimeCommand, InboundEvent, OpenedStreamDelivery, StreamConfig},
    wire::stream::{CloseCode, CloseTarget},
    Peer, QlError, StreamId,
};

#[derive(Clone)]
pub struct RuntimeHandle {
    pub(crate) tx: Sender<RuntimeCommand>,
    pub(crate) stream_send_buffer_bytes: usize,
}

pub struct DuplexStream {
    pub stream_id: StreamId,
    pub request: OutboundByteStream,
    pub response: InboundByteStream,
}

#[derive(Debug)]
pub struct InboundStream {
    pub stream_id: StreamId,
    pub request_head: Vec<u8>,
    pub request: InboundByteStream,
    pub response: OutboundByteStream,
}

pub struct InboundByteStream {
    stream_id: StreamId,
    target: CloseTarget,
    rx: Receiver<InboundEvent>,
    tx: Sender<RuntimeCommand>,
    finished: bool,
}

impl std::fmt::Debug for InboundByteStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundByteStream")
            .field("stream_id", &self.stream_id)
            .field("target", &self.target)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

pub struct OutboundByteStream {
    stream_id: StreamId,
    target: CloseTarget,
    writer: Option<piper::Writer>,
    tx: Sender<RuntimeCommand>,
}

impl std::fmt::Debug for OutboundByteStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundByteStream")
            .field("stream_id", &self.stream_id)
            .field("target", &self.target)
            .field("closed", &self.writer.is_none())
            .finish_non_exhaustive()
    }
}

impl InboundByteStream {
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
        if self.finished {
            return Ok(None);
        }
        match self.rx.recv().await {
            Ok(InboundEvent::Data(bytes)) => Ok(Some(bytes)),
            Ok(InboundEvent::Finished) => {
                self.finished = true;
                Ok(None)
            }
            Ok(InboundEvent::Failed(error)) => {
                self.finished = true;
                Err(error)
            }
            Err(_) => {
                self.finished = true;
                Err(QlError::Cancelled)
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

impl Drop for InboundByteStream {
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

impl OutboundByteStream {
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

impl Drop for OutboundByteStream {
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

    pub async fn open_stream(
        &self,
        request_head: Vec<u8>,
        config: StreamConfig,
    ) -> Result<DuplexStream, QlError> {
        let (request_reader, request_writer) = piper::pipe(self.stream_send_buffer_bytes);
        let (start_tx, start_rx) = oneshot::channel();

        self.tx
            .send(RuntimeCommand::OpenStream {
                request_head,
                request_reader,
                start: start_tx,
                config,
            })
            .await
            .map_err(|_| QlError::Cancelled)?;

        let OpenedStreamDelivery {
            stream_id,
            response,
        } = start_rx.await.unwrap_or(Err(QlError::Cancelled))?;

        Ok(DuplexStream {
            stream_id,
            request: OutboundByteStream::new(
                stream_id,
                CloseTarget::Request,
                request_writer,
                self.tx.clone(),
            ),
            response: InboundByteStream::new(
                stream_id,
                CloseTarget::Response,
                response,
                self.tx.clone(),
            ),
        })
    }
}

impl RuntimeHandle {
    #[inline]
    #[track_caller]
    fn send(&self, cmd: RuntimeCommand) {
        self.tx.send_blocking(cmd).expect("runtime is alive")
    }
}
