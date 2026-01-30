use bc_components::{EncapsulationPublicKey, SigningPublicKey, XID};
use dcbor::CBOR;
use oneshot::Receiver;

use crate::{
    runtime::{RequestConfig, RuntimeCommand},
    wire::message::MessageKind,
    MessageId, QlError, RouteId,
};

#[derive(Clone)]
pub struct RuntimeHandle {
    pub(crate) tx: async_channel::Sender<RuntimeCommand>,
}

pub struct Response {
    rx: Receiver<Result<CBOR, QlError>>,
}

impl Response {
    pub async fn recv(self) -> Result<CBOR, QlError> {
        self.rx.await.unwrap_or(Err(QlError::Cancelled))
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

    pub async fn send_request(
        &self,
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
        config: RequestConfig,
    ) -> Result<Response, QlError> {
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
        Ok(Response { rx })
    }

    pub async fn send_event(
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

    pub async fn send_response(
        &self,
        id: MessageId,
        recipient: XID,
        payload: CBOR,
        kind: MessageKind,
    ) -> Result<(), QlError> {
        self.tx
            .send(RuntimeCommand::SendResponse {
                id,
                recipient,
                payload,
                kind,
            })
            .await
            .map_err(|_| QlError::Cancelled)
    }
}
