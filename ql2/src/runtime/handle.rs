use std::{
    future::Future,
    marker::PhantomData,
    pin::{pin, Pin},
    task::{Context, Poll},
};

use bc_components::{EncapsulationPublicKey, SigningPublicKey, XID};
use dcbor::CBOR;
use oneshot::Receiver;

use crate::{
    runtime::{RequestConfig, RuntimeCommand},
    wire::message::Ack,
    Event, QlCodec, QlError, RequestResponse, RouteId,
};

#[derive(Clone)]
pub struct RuntimeHandle {
    pub(crate) tx: async_channel::Sender<RuntimeCommand>,
}

pub struct Response<T> {
    rx: Receiver<Result<CBOR, QlError>>,
    _type: PhantomData<fn() -> T>,
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
            Ok(T::try_from(payload).map_err(|_| QlError::InvalidPayload)?)
        })
    }
}

impl RuntimeHandle {
    pub(crate) fn new(tx: async_channel::Sender<RuntimeCommand>) -> Self {
        Self { tx }
    }

    pub async fn register_peer(
        &self,
        peer: XID,
        signing_key: SigningPublicKey,
        encapsulation_key: EncapsulationPublicKey,
    ) -> Result<(), QlError> {
        self.tx
            .send(RuntimeCommand::RegisterPeer {
                peer,
                signing_key,
                encapsulation_key,
            })
            .await
            .map_err(|_| QlError::Cancelled)
    }

    pub async fn connect(&self, peer: XID) -> Result<(), QlError> {
        self.tx
            .send(RuntimeCommand::Connect { peer })
            .await
            .map_err(|_| QlError::Cancelled)
    }

    pub async fn send_incoming(&self, bytes: Vec<u8>) -> Result<(), QlError> {
        self.tx
            .send(RuntimeCommand::Incoming(bytes))
            .await
            .map_err(|_| QlError::Cancelled)
    }

    pub async fn request<M>(
        &self,
        message: M,
        recipient: XID,
        config: RequestConfig,
    ) -> Result<Response<M::Response>, QlError>
    where
        M: RequestResponse,
    {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(RuntimeCommand::SendRequest {
                recipient,
                route_id: M::ID,
                payload: message.into(),
                respond_to: tx,
                config,
            })
            .await
            .map_err(|_| QlError::Cancelled)?;
        Ok(Response {
            rx,
            _type: PhantomData,
        })
    }

    pub async fn send_event<M>(&self, message: M, recipient: XID) -> Result<(), QlError>
    where
        M: Event,
    {
        self.send_event_raw(recipient, M::ID, message.into()).await
    }

    pub async fn send_event_with_ack<M>(
        &self,
        message: M,
        recipient: XID,
        config: RequestConfig,
    ) -> Result<Response<Ack>, QlError>
    where
        M: Event,
    {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(RuntimeCommand::SendRequest {
                recipient,
                route_id: M::ID,
                payload: message.into(),
                respond_to: tx,
                config,
            })
            .await
            .map_err(|_| QlError::Cancelled)?;
        Ok(Response {
            rx,
            _type: PhantomData,
        })
    }

    pub async fn send_event_raw(
        &self,
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
    ) -> Result<(), QlError> {
        self.tx
            .send(RuntimeCommand::SendEvent {
                recipient,
                route_id,
                payload,
            })
            .await
            .map_err(|_| QlError::Cancelled)
    }

    pub async fn send_request_raw(
        &self,
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
        config: RequestConfig,
    ) -> Result<Response<CBOR>, QlError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(RuntimeCommand::SendRequest {
                recipient,
                route_id,
                payload,
                respond_to: tx,
                config,
            })
            .await
            .map_err(|_| QlError::Cancelled)?;
        Ok(Response {
            rx,
            _type: PhantomData,
        })
    }
}
