use std::{
    future::Future,
    marker::PhantomData,
    pin::{pin, Pin},
    task::{Context, Poll},
};

use bc_components::{EncapsulationPublicKey, SigningPublicKey, XID};
use dcbor::CBOR;

use crate::{
    runtime::{internal::RuntimeCommand, RequestConfig},
    wire::message::Ack,
    Event, QlCodec, QlError, RequestResponse, RouteId,
};

#[derive(Clone)]
pub struct RuntimeHandle {
    pub(crate) tx: async_channel::Sender<RuntimeCommand>,
}

pub struct Response<T> {
    rx: oneshot::Receiver<Result<CBOR, QlError>>,
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
    pub fn register_peer(
        &self,
        peer: XID,
        signing_key: SigningPublicKey,
        encapsulation_key: EncapsulationPublicKey,
    ) -> Result<(), QlError> {
        self.tx
            .send_blocking(RuntimeCommand::RegisterPeer {
                peer,
                signing_key,
                encapsulation_key,
            })
            .map_err(|_| QlError::Cancelled)
    }

    pub fn connect(&self, peer: XID) -> Result<(), QlError> {
        self.tx
            .send_blocking(RuntimeCommand::Connect { peer })
            .map_err(|_| QlError::Cancelled)
    }

    pub fn send_incoming(&self, bytes: Vec<u8>) -> Result<(), QlError> {
        self.tx
            .send_blocking(RuntimeCommand::Incoming(bytes))
            .map_err(|_| QlError::Cancelled)
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
        self.tx
            .send_blocking(RuntimeCommand::SendRequest {
                recipient,
                route_id: M::ID,
                payload: message.into(),
                respond_to: tx,
                config,
            })
            .unwrap();
        Response {
            rx,
            _type: PhantomData,
        }
    }

    pub fn send_event<M>(&self, message: M, recipient: XID) -> Result<(), QlError>
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
    ) -> Result<Response<Ack>, QlError>
    where
        M: Event,
    {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_blocking(RuntimeCommand::SendRequest {
                recipient,
                route_id: M::ID,
                payload: message.into(),
                respond_to: tx,
                config,
            })
            .map_err(|_| QlError::Cancelled)?;
        Ok(Response {
            rx,
            _type: PhantomData,
        })
    }

    pub fn send_event_raw(
        &self,
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
    ) -> Result<(), QlError> {
        self.tx
            .send_blocking(RuntimeCommand::SendEvent {
                recipient,
                route_id,
                payload,
            })
            .map_err(|_| QlError::Cancelled)
    }

    pub fn send_request_raw(
        &self,
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
        config: RequestConfig,
    ) -> Result<Response<CBOR>, QlError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_blocking(RuntimeCommand::SendRequest {
                recipient,
                route_id,
                payload,
                respond_to: tx,
                config,
            })
            .map_err(|_| QlError::Cancelled)?;
        Ok(Response {
            rx,
            _type: PhantomData,
        })
    }
}
