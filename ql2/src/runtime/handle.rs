use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use async_channel::Sender;
use bc_components::{MLDSAPublicKey, MLKEMPublicKey, XID};
use futures_lite::future::poll_fn;

use crate::{
    pipe,
    runtime::{
        internal::{InboundStreamItem, RuntimeCommand},
        AcceptedStreamDelivery, StreamConfig,
    },
    wire::stream::{Direction, RejectCode, ResetCode},
    QlError, RouteId, StreamId,
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
    pub sender: XID,
    pub recipient: XID,
    pub route_id: RouteId,
    pub stream_id: StreamId,
    pub request_head: Vec<u8>,
    pub response_expected: bool,
    pub request: InboundByteStream,
    pub respond_to: StreamResponder,
}

#[derive(Debug, Clone)]
pub struct StreamResponder {
    stream_id: StreamId,
    recipient: XID,
    pipe_size_bytes: usize,
    tx: async_channel::Sender<RuntimeCommand>,
}

pub struct InboundByteStream {
    sender: XID,
    stream_id: StreamId,
    dir: Direction,
    rx: async_channel::Receiver<InboundStreamItem>,
    tx: Sender<RuntimeCommand>,
    finished: bool,
}

impl std::fmt::Debug for InboundByteStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundByteStream")
            .field("sender", &self.sender)
            .field("stream_id", &self.stream_id)
            .field("dir", &self.dir)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

pub struct OutboundByteStream {
    recipient: XID,
    stream_id: StreamId,
    dir: Direction,
    pipe: Option<pipe::PipeWriter>,
    tx: Sender<RuntimeCommand>,
}

pub struct PendingAccept {
    rx: oneshot::Receiver<Result<AcceptedStreamDelivery, QlError>>,
}

impl Future for PendingAccept {
    type Output = Result<AcceptedStream, QlError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        Pin::new(&mut this.rx).poll(cx).map(|result| match result {
            Ok(Ok(delivery)) => {
                let AcceptedStreamDelivery {
                    peer,
                    stream_id,
                    response_head,
                    rx,
                    tx,
                } = delivery;
                Ok(AcceptedStream {
                    stream_id,
                    response_head,
                    response: InboundByteStream::new(peer, stream_id, Direction::Response, rx, tx),
                })
            }
            Ok(Err(error)) => Err(error),
            Err(_) => Err(QlError::Cancelled),
        })
    }
}

impl InboundByteStream {
    pub(crate) fn new(
        sender: XID,
        stream_id: StreamId,
        dir: Direction,
        rx: async_channel::Receiver<InboundStreamItem>,
        tx: Sender<RuntimeCommand>,
    ) -> Self {
        Self {
            sender,
            stream_id,
            dir,
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
            Ok(InboundStreamItem::Chunk(chunk)) => {
                let len = chunk.len();
                let _ = self
                    .tx
                    .send(RuntimeCommand::AdvanceInboundCredit {
                        sender: self.sender,
                        stream_id: self.stream_id,
                        dir: self.dir,
                        amount: len as u64,
                    })
                    .await;
                Ok(Some(chunk))
            }
            Ok(InboundStreamItem::Finished) => {
                self.finished = true;
                Ok(None)
            }
            Ok(InboundStreamItem::Error(error)) => {
                self.finished = true;
                Err(error)
            }
            Err(_) => {
                self.finished = true;
                Err(QlError::Cancelled)
            }
        }
    }

    pub async fn reset(mut self, code: ResetCode) -> Result<(), QlError> {
        self.finished = true;
        self.tx
            .send(RuntimeCommand::ResetInbound {
                sender: self.sender,
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
            sender: self.sender,
            stream_id: self.stream_id,
            dir: self.dir,
            code: ResetCode::Cancelled,
        });
    }
}

impl OutboundByteStream {
    pub(crate) fn new(
        recipient: XID,
        stream_id: StreamId,
        dir: Direction,
        pipe: pipe::PipeWriter,
        tx: Sender<RuntimeCommand>,
    ) -> Self {
        Self {
            recipient,
            stream_id,
            dir,
            pipe: Some(pipe),
            tx,
        }
    }

    pub async fn write(&mut self, bytes: &[u8]) -> Result<usize, QlError> {
        let pipe = self.pipe.as_mut().expect("stream not finished or reset");
        let written = poll_fn(|cx| pipe.poll_write(cx, bytes)).await?;
        // TODO: We currently nudge the runtime after every successful write. If this becomes noisy,
        // add a coalesced readiness bit rather than buffering writes in another queue again.
        self.tx
            .try_send(RuntimeCommand::PollStream {
                peer: self.recipient,
                stream_id: self.stream_id,
            })
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
            .try_send(RuntimeCommand::PollStream {
                peer: self.recipient,
                stream_id: self.stream_id,
            })
            .map_err(|_| QlError::Cancelled)?;
        // TODO: closed() resolves when the runtime closes this outbound side, which currently
        // means finish acked, reset, or abort. Revisit if we want a stricter finish-only signal.
        pipe.closed().await;
        Ok(())
    }

    pub async fn reset(mut self, code: ResetCode) -> Result<(), QlError> {
        self.pipe.take();
        self.tx
            .send(RuntimeCommand::ResetOutbound {
                recipient: self.recipient,
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
            recipient: self.recipient,
            stream_id: self.stream_id,
            dir: self.dir,
            code: ResetCode::Cancelled,
        });
    }
}

impl StreamResponder {
    pub(crate) fn new(
        stream_id: StreamId,
        recipient: XID,
        pipe_size_bytes: usize,
        tx: async_channel::Sender<RuntimeCommand>,
    ) -> Self {
        Self {
            stream_id,
            recipient,
            pipe_size_bytes,
            tx,
        }
    }

    pub fn accept(self, response_head: Vec<u8>) -> Result<OutboundByteStream, QlError> {
        let (response_pipe, response_writer) = pipe::pipe(self.pipe_size_bytes);
        self.tx
            .send_blocking(RuntimeCommand::AcceptStream {
                recipient: self.recipient,
                stream_id: self.stream_id,
                response_head,
                response_pipe,
            })
            .map_err(|_| QlError::Cancelled)?;
        Ok(OutboundByteStream::new(
            self.recipient,
            self.stream_id,
            Direction::Response,
            response_writer,
            self.tx,
        ))
    }

    pub fn reject(self, code: RejectCode) -> Result<(), QlError> {
        self.tx
            .try_send(RuntimeCommand::RejectStream {
                recipient: self.recipient,
                stream_id: self.stream_id,
                code,
            })
            .map_err(|_| QlError::Cancelled)
    }
}

impl RuntimeHandle {
    pub fn register_peer(
        &self,
        peer: XID,
        signing_key: MLDSAPublicKey,
        encapsulation_key: MLKEMPublicKey,
    ) {
        self.send(RuntimeCommand::RegisterPeer {
            peer,
            signing_key,
            encapsulation_key,
        })
    }

    pub fn connect(&self, peer: XID) -> Result<(), QlError> {
        self.tx
            .send_blocking(RuntimeCommand::Connect { peer })
            .map_err(|_| QlError::Cancelled)
    }

    pub fn unpair(&self, peer: XID) -> Result<(), QlError> {
        self.tx
            .send_blocking(RuntimeCommand::Unpair { peer })
            .map_err(|_| QlError::Cancelled)
    }

    pub fn send_incoming(&self, bytes: Vec<u8>) {
        self.send(RuntimeCommand::Incoming(bytes))
    }

    pub async fn open_stream(
        &self,
        recipient: XID,
        route_id: RouteId,
        request_head: Vec<u8>,
        response_expected: bool,
        config: StreamConfig,
    ) -> Result<PendingStream, QlError> {
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (request_pipe, request_writer) = pipe::pipe(self.pipe_size_bytes);
        let (start_tx, start_rx) = oneshot::channel();
        self.tx
            .send(RuntimeCommand::OpenStream {
                recipient,
                route_id,
                request_head,
                response_expected,
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
                recipient,
                stream_id,
                Direction::Request,
                request_writer,
                self.tx.clone(),
            ),
            accepted: PendingAccept { rx: accepted_rx },
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
