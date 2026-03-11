use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use async_channel::Sender;

use crate::{
    runtime::pipe::{self, ReadReady},
    Peer,
    runtime::{
        command::RuntimeCommand,
        AcceptedStreamDelivery, StreamConfig,
    },
    wire::stream::{Direction, RejectCode, ResetCode},
    QlError, StreamId,
};

#[derive(Clone)]
pub struct RuntimeHandle {
    pub(crate) tx: async_channel::Sender<RuntimeCommand>,
    pub(crate) pipe_size_bytes: usize,
}

pub struct PendingStream {
    pub request: OutboundByteStream,
    pub accepted: PendingAccept,
}

#[derive(Debug)]
pub struct AcceptedStream {
    pub stream_id: StreamId,
    pub response_head: Vec<u8>,
    pub response: InboundByteStream,
}

#[derive(Debug)]
pub struct InboundStream {
    pub stream_id: StreamId,
    pub request_head: Vec<u8>,
    pub request: InboundByteStream,
    pub respond_to: StreamResponder,
}

#[derive(Debug)]
pub struct StreamResponder {
    stream_id: StreamId,
    pipe_size_bytes: usize,
    tx: async_channel::Sender<RuntimeCommand>,
    armed: bool,
}

pub struct InboundByteStream {
    stream_id: StreamId,
    dir: Direction,
    pipe: pipe::PipeReader<QlError>,
    tx: Sender<RuntimeCommand>,
    finished: bool,
}

impl std::fmt::Debug for InboundByteStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundByteStream")
            .field("stream_id", &self.stream_id)
            .field("dir", &self.dir)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

pub struct OutboundByteStream {
    stream_id: StreamId,
    dir: Direction,
    pipe: Option<pipe::PipeWriter<QlError>>,
    tx: Sender<RuntimeCommand>,
}

pub struct PendingAccept {
    stream_id: StreamId,
    rx: Option<oneshot::Receiver<Result<AcceptedStreamDelivery, QlError>>>,
    tx: Sender<RuntimeCommand>,
}

impl Future for PendingAccept {
    type Output = Result<AcceptedStream, QlError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let Some(rx) = this.rx.as_mut() else {
            return Poll::Ready(Err(QlError::Cancelled));
        };
        Pin::new(rx).poll(cx).map(|result| match result {
            Ok(Ok(delivery)) => {
                let AcceptedStreamDelivery {
                    stream_id,
                    response_head,
                    response,
                    tx,
                } = delivery;
                this.rx = None;
                Ok(AcceptedStream {
                    stream_id,
                    response_head,
                    response: InboundByteStream::new(stream_id, Direction::Response, response, tx),
                })
            }
            Ok(Err(error)) => {
                this.rx = None;
                Err(error)
            }
            Err(_) => {
                this.rx = None;
                Err(QlError::Cancelled)
            }
        })
    }
}

impl Drop for PendingAccept {
    fn drop(&mut self) {
        if self.rx.take().is_none() {
            return;
        }
        let _ = self.tx.try_send(RuntimeCommand::PendingAcceptDropped {
            stream_id: self.stream_id,
        });
    }
}

impl InboundByteStream {
    pub(crate) fn new(
        stream_id: StreamId,
        dir: Direction,
        pipe: pipe::PipeReader<QlError>,
        tx: Sender<RuntimeCommand>,
    ) -> Self {
        Self {
            stream_id,
            dir,
            pipe,
            tx,
            finished: false,
        }
    }

    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, QlError> {
        if self.finished {
            return Ok(None);
        }
        match self.pipe.ready().await {
            ReadReady::Data => {
                let chunk = self.pipe.peek_buf().to_vec();
                let len = chunk.len();
                self.pipe.consume(len);
                if len > 0 {
                    let _ = self
                        .tx
                        .send(RuntimeCommand::AdvanceInboundCredit {
                            stream_id: self.stream_id,
                            dir: self.dir,
                            amount: len as u64,
                        })
                        .await;
                }
                Ok(Some(chunk))
            }
            ReadReady::Eof => {
                self.finished = true;
                Ok(None)
            }
            ReadReady::Error(error) => {
                self.finished = true;
                Err(error)
            }
        }
    }

    pub async fn reset(mut self, code: ResetCode) -> Result<(), QlError> {
        self.finished = true;
        self.tx
            .send(RuntimeCommand::ResetInbound {
                stream_id: self.stream_id,
                dir: self.dir,
                code,
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
        let _ = self.tx.try_send(RuntimeCommand::ResetInbound {
            stream_id: self.stream_id,
            dir: self.dir,
            code: ResetCode::Cancelled,
        });
    }
}

impl OutboundByteStream {
    pub(crate) fn new(
        stream_id: StreamId,
        dir: Direction,
        pipe: pipe::PipeWriter<QlError>,
        tx: Sender<RuntimeCommand>,
    ) -> Self {
        Self {
            stream_id,
            dir,
            pipe: Some(pipe),
            tx,
        }
    }

    pub async fn write(&mut self, bytes: &[u8]) -> Result<usize, QlError> {
        let pipe = self.pipe.as_mut().expect("stream not finished or reset");
        let written = pipe.write(bytes).await?;
        self.tx
            .try_send(RuntimeCommand::PollStream { stream_id: self.stream_id })
            .map_err(|_| QlError::Cancelled)?;
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
        let Some(mut pipe) = self.pipe.take() else {
            return Ok(());
        };
        pipe.finish();
        self.tx
            .try_send(RuntimeCommand::PollStream { stream_id: self.stream_id })
            .map_err(|_| QlError::Cancelled)?;
        pipe.closed().await;
        Ok(())
    }

    pub async fn reset(mut self, code: ResetCode) -> Result<(), QlError> {
        self.pipe.take();
        self.tx
            .send(RuntimeCommand::ResetOutbound {
                stream_id: self.stream_id,
                dir: self.dir,
                code,
            })
            .await
            .map_err(|_| QlError::Cancelled)
    }
}

impl Drop for OutboundByteStream {
    fn drop(&mut self) {
        if self.pipe.take().is_none() {
            return;
        }
        let _ = self.tx.try_send(RuntimeCommand::ResetOutbound {
            stream_id: self.stream_id,
            dir: self.dir,
            code: ResetCode::Cancelled,
        });
    }
}

impl StreamResponder {
    pub(crate) fn new(
        stream_id: StreamId,
        pipe_size_bytes: usize,
        tx: async_channel::Sender<RuntimeCommand>,
    ) -> Self {
        Self {
            stream_id,
            pipe_size_bytes,
            tx,
            armed: true,
        }
    }

    pub fn accept(mut self, response_head: Vec<u8>) -> Result<OutboundByteStream, QlError> {
        self.armed = false;
        let (response_pipe, response_writer) = pipe::pipe(self.pipe_size_bytes);
        self.tx
            .send_blocking(RuntimeCommand::AcceptStream {
                stream_id: self.stream_id,
                response_head,
                response_pipe,
            })
            .map_err(|_| QlError::Cancelled)?;
        Ok(OutboundByteStream::new(
            self.stream_id,
            Direction::Response,
            response_writer,
            self.tx.clone(),
        ))
    }

    pub fn reject(mut self, code: RejectCode) -> Result<(), QlError> {
        self.armed = false;
        self.tx
            .try_send(RuntimeCommand::RejectStream {
                stream_id: self.stream_id,
                code,
            })
            .map_err(|_| QlError::Cancelled)
    }
}

impl Drop for StreamResponder {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = self
            .tx
            .try_send(RuntimeCommand::ResponderDropped { stream_id: self.stream_id });
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

    pub async fn open_stream(&self, request_head: Vec<u8>, config: StreamConfig) -> Result<PendingStream, QlError> {
        let (request_pipe, request_writer) = pipe::pipe(self.pipe_size_bytes);
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (start_tx, start_rx) = oneshot::channel();

        self.tx
            .send(RuntimeCommand::OpenStream {
                request_head,
                request_pipe,
                accepted: accepted_tx,
                start: start_tx,
                config,
            })
            .await
            .map_err(|_| QlError::Cancelled)?;

        let stream_id = start_rx.await.unwrap_or(Err(QlError::Cancelled))?;

        Ok(PendingStream {
            request: OutboundByteStream::new(
                stream_id,
                Direction::Request,
                request_writer,
                self.tx.clone(),
            ),
            accepted: PendingAccept {
                stream_id,
                rx: Some(accepted_rx),
                tx: self.tx.clone(),
            },
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
