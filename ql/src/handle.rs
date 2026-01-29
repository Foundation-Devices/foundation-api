use std::{
    future::Future,
    pin::{pin, Pin},
    task::{Context, Poll},
};

use async_channel::Sender;
use bc_components::{EncapsulationPublicKey, SigningPublicKey, XID};
use dcbor::CBOR;

use crate::{
    runtime::{RequestConfig, RuntimeEvent},
    wire::Ack,
    Event, QlCodec, QlError, RequestResponse,
};

#[derive(Debug, Clone)]
pub struct RuntimeHandle {
    pub(crate) tx: Sender<RuntimeEvent>,
}

pub struct Response<T> {
    rx: oneshot::Receiver<Result<CBOR, QlError>>,
    _type: std::marker::PhantomData<fn() -> T>,
}

impl<T> Future for Response<T>
where
    T: QlCodec,
{
    type Output = Result<T, QlError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        pin!(&mut self.rx).poll(cx).map(|result| {
            let payload = result.unwrap_or(Err(QlError::Cancelled))?;
            Ok(T::try_from(payload)?)
        })
    }
}

impl RuntimeHandle {
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
            .send_blocking(RuntimeEvent::SendRequest {
                recipient,
                route_id: M::ID,
                payload: message.into(),
                respond_to: tx,
                config,
            })
            .unwrap();
        Response {
            rx,
            _type: Default::default(),
        }
    }

    pub fn send_event<M>(&self, message: M, recipient: XID) -> Result<(), QlError>
    where
        M: Event,
    {
        self.tx
            .send_blocking(RuntimeEvent::SendEvent {
                recipient,
                route_id: M::ID,
                payload: message.into(),
            })
            .map_err(|_| QlError::Cancelled)
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
        let _ = self.tx.send_blocking(RuntimeEvent::SendRequest {
            recipient,
            route_id: M::ID,
            payload: message.into(),
            respond_to: tx,
            config,
        });
        Response {
            rx,
            _type: Default::default(),
        }
    }

    pub fn send_pairing_request(
        &self,
        recipient_signing_key: SigningPublicKey,
        recipient_encapsulation_key: EncapsulationPublicKey,
    ) -> Result<(), QlError> {
        self.tx
            .send_blocking(RuntimeEvent::SendPairing {
                recipient_signing_key,
                recipient_encapsulation_key,
            })
            .map_err(|_| QlError::Cancelled)
    }

    pub fn send_incoming(&self, bytes: Vec<u8>) -> Result<(), QlError> {
        self.tx
            .send_blocking(RuntimeEvent::Incoming { bytes })
            .map_err(|_| QlError::Cancelled)
    }
}
