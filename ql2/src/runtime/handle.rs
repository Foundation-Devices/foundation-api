use std::{
    future::Future,
    marker::PhantomData,
    pin::{pin, Pin},
    task::{Context, Poll},
};

use async_channel::Sender;
use bc_components::{MLDSAPublicKey, MLKEMPublicKey, XID};
use dcbor::CBOR;

use crate::{
    runtime::{
        internal::{InboundStreamDelivery, InboundStreamItem, OutboundStreamInput, RuntimeCommand},
        RequestConfig,
    },
    wire::message::Ack,
    Event, MessageId, QlCodec, QlError, QlStream, QlUpload, RequestResponse, RouteId,
};

#[derive(Clone)]
pub struct RuntimeHandle {
    pub(crate) tx: async_channel::Sender<RuntimeCommand>,
}

pub struct Response<T> {
    rx: oneshot::Receiver<Result<CBOR, QlError>>,
    _type: PhantomData<fn() -> T>,
}

pub struct StreamResponse<T> {
    rx: oneshot::Receiver<Result<InboundStreamDelivery, QlError>>,
    _type: PhantomData<fn() -> T>,
}

pub struct InboundStream<T> {
    pub meta: T,
    pub body: InboundByteStream,
}

pub struct InboundByteStream {
    sender: XID,
    transfer_id: MessageId,
    rx: async_channel::Receiver<InboundStreamItem>,
    tx: Sender<RuntimeCommand>,
    finished: bool,
}

impl std::fmt::Debug for InboundByteStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundByteStream")
            .field("sender", &self.sender)
            .field("transfer_id", &self.transfer_id)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

pub struct OutboundTransfer {
    recipient: XID,
    transfer_id: MessageId,
    chunk_tx: Option<Sender<OutboundStreamInput>>,
    tx: Sender<RuntimeCommand>,
}

pub struct UploadRequest<R> {
    pub transfer: OutboundTransfer,
    pub response: Response<R>,
}

impl<T> Response<T> {
    pub async fn recv(self) -> Result<CBOR, QlError> {
        self.rx.await.unwrap_or(Err(QlError::Cancelled))
    }
}

impl<T> Future for Response<T>
where
    T: QlCodec,
{
    type Output = Result<T, QlError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        pin!(&mut self.rx).poll(cx).map(|result| {
            let payload = result.unwrap_or(Err(QlError::Cancelled))?;
            T::try_from(payload).map_err(|_| QlError::InvalidPayload)
        })
    }
}

impl<T> StreamResponse<T> {
    pub async fn recv(self) -> Result<InboundStream<CBOR>, QlError> {
        let delivery = self.rx.await.unwrap_or(Err(QlError::Cancelled))?;
        let InboundStreamDelivery {
            peer,
            transfer_id,
            meta,
            rx,
            tx,
        } = delivery;
        Ok(InboundStream {
            meta,
            body: InboundByteStream::new(peer, transfer_id, rx, tx),
        })
    }
}

impl<T> Future for StreamResponse<T>
where
    T: QlCodec,
{
    type Output = Result<InboundStream<T>, QlError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        pin!(&mut self.rx).poll(cx).map(|result| {
            let delivery = result.unwrap_or(Err(QlError::Cancelled))?;
            let InboundStreamDelivery {
                peer,
                transfer_id,
                meta,
                rx,
                tx,
            } = delivery;
            let meta = T::try_from(meta).map_err(|_| QlError::InvalidPayload)?;
            Ok(InboundStream {
                meta,
                body: InboundByteStream::new(peer, transfer_id, rx, tx),
            })
        })
    }
}

impl<R> UploadRequest<R>
where
    R: QlCodec,
{
    pub async fn finish(self) -> Result<R, QlError> {
        let Self { transfer, response } = self;
        transfer.finish().await?;
        response.await
    }
}

impl InboundByteStream {
    pub(crate) fn new(
        sender: XID,
        transfer_id: MessageId,
        rx: async_channel::Receiver<InboundStreamItem>,
        tx: Sender<RuntimeCommand>,
    ) -> Self {
        Self {
            sender,
            transfer_id,
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
            Ok(InboundStreamItem::Chunk(chunk)) => Ok(Some(chunk)),
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
                Err(QlError::TransferCancelled {
                    id: self.transfer_id,
                })
            }
        }
    }
}

impl Drop for InboundByteStream {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = self.tx.try_send(RuntimeCommand::CancelInboundTransfer {
            sender: self.sender,
            transfer_id: self.transfer_id,
        });
    }
}

impl OutboundTransfer {
    pub(crate) fn new(
        recipient: XID,
        transfer_id: MessageId,
        chunk_tx: Sender<OutboundStreamInput>,
        tx: Sender<RuntimeCommand>,
    ) -> Self {
        Self {
            recipient,
            transfer_id,
            chunk_tx: Some(chunk_tx),
            tx,
        }
    }

    pub async fn write_next(&mut self, chunk: Vec<u8>) -> Result<(), QlError> {
        let chunk_tx = self
            .chunk_tx
            .as_ref()
            .expect("transfer not finished or cancelled");
        chunk_tx
            .send(OutboundStreamInput::Chunk(chunk))
            .await
            .map_err(|_| QlError::TransferCancelled {
                id: self.transfer_id,
            })?;
        self.tx
            .send(RuntimeCommand::PollOutboundTransfer {
                recipient: self.recipient,
                transfer_id: self.transfer_id,
            })
            .await
            .map_err(|_| QlError::Cancelled)?;
        Ok(())
    }

    pub async fn finish(mut self) -> Result<(), QlError> {
        let Some(chunk_tx) = self.chunk_tx.take() else {
            return Ok(());
        };
        if chunk_tx.send(OutboundStreamInput::Finish).await.is_err() {
            return Ok(());
        }
        self.tx
            .send(RuntimeCommand::PollOutboundTransfer {
                recipient: self.recipient,
                transfer_id: self.transfer_id,
            })
            .await
            .map_err(|_| QlError::Cancelled)?;
        chunk_tx.closed().await;
        Ok(())
    }

    pub async fn cancel(mut self) -> Result<(), QlError> {
        self.chunk_tx.take();
        self.tx
            .send(RuntimeCommand::CancelOutboundTransfer {
                recipient: self.recipient,
                transfer_id: self.transfer_id,
            })
            .await
            .map_err(|_| QlError::Cancelled)
    }
}

impl Drop for OutboundTransfer {
    fn drop(&mut self) {
        if self.chunk_tx.take().is_none() {
            return;
        }
        let _ = self.tx.try_send(RuntimeCommand::CancelOutboundTransfer {
            recipient: self.recipient,
            transfer_id: self.transfer_id,
        });
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

    pub fn request<M>(
        &self,
        message: M,
        recipient: XID,
        config: RequestConfig,
    ) -> Response<M::Response>
    where
        M: RequestResponse,
    {
        let (tx, rx) = oneshot::channel();
        self.send(RuntimeCommand::SendRequest {
            recipient,
            route_id: M::ID,
            payload: message.into(),
            respond_to: tx,
            config,
        });
        Response {
            rx,
            _type: PhantomData,
        }
    }

    pub fn request_stream<M>(
        &self,
        message: M,
        recipient: XID,
        config: RequestConfig,
    ) -> StreamResponse<M::StreamMeta>
    where
        M: QlStream,
    {
        let (tx, rx) = oneshot::channel();
        self.send(RuntimeCommand::SendStreamRequest {
            recipient,
            route_id: M::ID,
            payload: message.into(),
            respond_to: tx,
            config,
        });
        StreamResponse {
            rx,
            _type: PhantomData,
        }
    }

    pub async fn request_upload<M>(
        &self,
        message: M,
        recipient: XID,
        config: RequestConfig,
    ) -> Result<UploadRequest<M::Response>, QlError>
    where
        M: QlUpload,
    {
        let upload = self
            .send_request_upload_raw(recipient, M::ID, message.into(), config)
            .await?;
        Ok(UploadRequest {
            transfer: upload.transfer,
            response: Response {
                rx: upload.response.rx,
                _type: PhantomData,
            },
        })
    }

    pub fn send_event<M>(&self, message: M, recipient: XID)
    where
        M: Event,
    {
        self.send_event_raw(recipient, M::ID, message.into())
    }

    pub fn send_event_with_ack<M>(
        &self,
        message: M,
        recipient: XID,
        config: RequestConfig,
    ) -> Response<Ack>
    where
        M: Event,
    {
        let (tx, rx) = oneshot::channel();
        self.send(RuntimeCommand::SendRequest {
            recipient,
            route_id: M::ID,
            payload: message.into(),
            respond_to: tx,
            config,
        });
        Response {
            rx,
            _type: PhantomData,
        }
    }

    pub fn send_event_raw(&self, recipient: XID, route_id: RouteId, payload: CBOR) {
        self.send(RuntimeCommand::SendEvent {
            recipient,
            route_id,
            payload,
        })
    }

    pub fn send_request_raw(
        &self,
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
        config: RequestConfig,
    ) -> Response<CBOR> {
        let (tx, rx) = oneshot::channel();
        self.send(RuntimeCommand::SendRequest {
            recipient,
            route_id,
            payload,
            respond_to: tx,
            config,
        });
        Response {
            rx,
            _type: PhantomData,
        }
    }

    pub fn send_request_stream_raw(
        &self,
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
        config: RequestConfig,
    ) -> StreamResponse<CBOR> {
        let (tx, rx) = oneshot::channel();
        self.send(RuntimeCommand::SendStreamRequest {
            recipient,
            route_id,
            payload,
            respond_to: tx,
            config,
        });
        StreamResponse {
            rx,
            _type: PhantomData,
        }
    }

    pub async fn send_request_upload_raw(
        &self,
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
        config: RequestConfig,
    ) -> Result<UploadRequest<CBOR>, QlError> {
        let (response_tx, response_rx) = oneshot::channel();
        let (chunk_tx, chunk_rx) = async_channel::bounded(1);
        let (start_tx, start_rx) = oneshot::channel();
        self.tx
            .send(RuntimeCommand::SendUploadRequest {
                recipient,
                route_id,
                payload,
                respond_to: response_tx,
                chunk_rx,
                start: start_tx,
                config,
            })
            .await
            .map_err(|_| QlError::Cancelled)?;

        let transfer_id = start_rx.await.unwrap_or(Err(QlError::Cancelled))?;

        Ok(UploadRequest {
            transfer: OutboundTransfer::new(recipient, transfer_id, chunk_tx, self.tx.clone()),
            response: Response {
                rx: response_rx,
                _type: PhantomData,
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
