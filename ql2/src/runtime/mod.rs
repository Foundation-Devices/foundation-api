use std::time::Duration;

use bc_components::XID;
use dcbor::CBOR;

use crate::{
    wire::message::{DecryptedMessage, MessageKind, Nack},
    MessageId, QlCodec, QlError,
};

#[derive(Debug, Clone, Default)]
pub struct RequestConfig {
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeConfig {
    pub handshake_timeout: Duration,
    pub default_request_timeout: Duration,
    pub message_expiration: Duration,
}

impl RuntimeConfig {
    pub fn new(handshake_timeout: Duration) -> Self {
        Self {
            handshake_timeout,
            default_request_timeout: Duration::from_secs(5),
            message_expiration: Duration::from_secs(30),
        }
    }

    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.default_request_timeout = timeout;
        self
    }

    pub fn with_message_expiration(mut self, expiration: Duration) -> Self {
        self.message_expiration = expiration;
        self
    }
}

#[derive(Debug)]
pub enum HandlerEvent {
    Request(InboundRequest),
    Event(InboundEvent),
}

#[derive(Debug)]
pub struct InboundRequest {
    pub message: DecryptedMessage,
    pub respond_to: Responder,
}

#[derive(Debug)]
pub struct InboundEvent {
    pub message: DecryptedMessage,
}

#[derive(Debug, Clone)]
pub struct Responder {
    id: MessageId,
    recipient: XID,
    tx: async_channel::Sender<RuntimeCommand>,
}

impl Responder {
    pub(crate) fn new(
        id: MessageId,
        recipient: XID,
        tx: async_channel::Sender<RuntimeCommand>,
    ) -> Self {
        Self { id, recipient, tx }
    }

    pub fn respond<R>(self, response: R) -> Result<(), QlError>
    where
        R: QlCodec,
    {
        self.tx
            .try_send(RuntimeCommand::SendResponse {
                id: self.id,
                recipient: self.recipient,
                payload: response.into(),
                kind: MessageKind::Response,
            })
            .map_err(|_| QlError::Cancelled)
    }

    pub fn respond_nack(self, reason: Nack) -> Result<(), QlError> {
        self.tx
            .try_send(RuntimeCommand::SendResponse {
                id: self.id,
                recipient: self.recipient,
                payload: CBOR::from(reason),
                kind: MessageKind::Nack,
            })
            .map_err(|_| QlError::Cancelled)
    }
}

pub struct Runtime<P> {
    platform: P,
    config: RuntimeConfig,
    rx: async_channel::Receiver<RuntimeCommand>,
    tx: async_channel::Sender<RuntimeCommand>,
}

pub mod handle;
pub(crate) mod internal;
pub use handle::{Response, RuntimeHandle};
pub use internal::{InitiatorStage, PeerSession, Token};
pub(crate) use internal::RuntimeCommand;
mod r#impl;

#[cfg(test)]
mod tests;

pub fn new_runtime<P: crate::platform::QlPlatform>(
    platform: P,
    config: RuntimeConfig,
) -> (Runtime<P>, RuntimeHandle) {
    let (tx, rx) = async_channel::unbounded();
    (
        Runtime {
            platform,
            config,
            rx,
            tx: tx.clone(),
        },
        RuntimeHandle::new(tx),
    )
}

 
