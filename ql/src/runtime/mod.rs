pub use handle::{Response, RuntimeHandle};
pub use internal::{InitiatorStage, PeerSession, Token};

mod core;
pub mod handle;
pub(crate) mod internal;
pub mod replay_cache;

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
pub struct KeepAliveConfig {
    pub interval: Duration,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeConfig {
    pub handshake_timeout: Duration,
    pub default_request_timeout: Duration,
    pub message_expiration: Duration,
    pub keep_alive: Option<KeepAliveConfig>,
}

impl RuntimeConfig {
    pub fn new(handshake_timeout: Duration) -> Self {
        Self {
            handshake_timeout,
            default_request_timeout: Duration::from_secs(5),
            message_expiration: Duration::from_secs(30),
            keep_alive: None,
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

    pub fn with_keep_alive(mut self, config: KeepAliveConfig) -> Self {
        self.keep_alive = Some(config);
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
    tx: async_channel::Sender<internal::RuntimeCommand>,
}

impl Responder {
    pub(crate) fn new(
        id: MessageId,
        recipient: XID,
        tx: async_channel::Sender<internal::RuntimeCommand>,
    ) -> Self {
        Self { id, recipient, tx }
    }

    pub fn respond<R>(self, response: R) -> Result<(), QlError>
    where
        R: QlCodec,
    {
        self.tx
            .try_send(internal::RuntimeCommand::SendResponse {
                id: self.id,
                recipient: self.recipient,
                payload: response.into(),
                kind: MessageKind::Response,
            })
            .map_err(|_| QlError::Cancelled)
    }

    pub fn respond_nack(self, reason: Nack) -> Result<(), QlError> {
        self.tx
            .try_send(internal::RuntimeCommand::SendResponse {
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
    rx: async_channel::Receiver<internal::RuntimeCommand>,
    tx: async_channel::WeakSender<internal::RuntimeCommand>,
}

pub fn new_runtime<P>(platform: P, config: RuntimeConfig) -> (Runtime<P>, RuntimeHandle)
where
    P: crate::platform::QlPlatform,
{
    let (tx, rx) = async_channel::unbounded();
    (
        Runtime {
            platform,
            config,
            rx,
            tx: tx.downgrade(),
        },
        RuntimeHandle { tx },
    )
}
