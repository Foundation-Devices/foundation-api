pub use handle::{ByteReader, ByteWriter, InboundStream, OutboundStream, RuntimeHandle};
pub use ql_fsm::{Peer, PeerStatus, QlFsmConfig, QlFsmError, SessionWriteId};
pub use ql_wire::{self as wire, CloseCode, CloseTarget, QlIdentity, StreamId, XID};

pub(crate) mod command;
pub(crate) mod driver;
pub mod handle;
pub mod platform;

#[cfg(test)]
mod tests;

use thiserror::Error;

use self::platform::QlPlatform;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum QlError {
    #[error("invalid payload")]
    InvalidPayload,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("expired")]
    Expired,
    #[error("signing failed")]
    SigningFailed,
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("missing stream")]
    MissingStream,
    #[error("stream is not writable")]
    NotWritable,
    #[error("session is closed")]
    SessionClosed,
    #[error("no peer bound")]
    NoPeerBound,
    #[error("send failed")]
    SendFailed,
    #[error("stream closed {code:?}")]
    StreamClosed {
        target: CloseTarget,
        code: CloseCode,
        payload: Vec<u8>,
    },
    #[error("cancelled")]
    Cancelled,
}

impl From<QlFsmError> for QlError {
    fn from(value: QlFsmError) -> Self {
        match value {
            QlFsmError::InvalidPayload => Self::InvalidPayload,
            QlFsmError::InvalidSignature => Self::InvalidSignature,
            QlFsmError::Expired => Self::Expired,
            QlFsmError::SigningFailed => Self::SigningFailed,
            QlFsmError::EncryptFailed => Self::EncryptFailed,
            QlFsmError::DecryptFailed => Self::DecryptFailed,
            QlFsmError::MissingStream => Self::MissingStream,
            QlFsmError::NotWritable => Self::NotWritable,
            QlFsmError::SessionClosed => Self::SessionClosed,
            QlFsmError::NoPeerBound => Self::NoPeerBound,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeConfig {
    pub fsm: QlFsmConfig,
    pub stream_send_buffer_bytes: usize,
    pub max_concurrent_message_writes: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            fsm: QlFsmConfig::default(),
            stream_send_buffer_bytes: 64 * 1024,
            max_concurrent_message_writes: 4,
        }
    }
}

impl RuntimeConfig {
    pub(crate) fn normalized(mut self) -> Self {
        self.stream_send_buffer_bytes = self.stream_send_buffer_bytes.max(1);
        self.max_concurrent_message_writes = self.max_concurrent_message_writes.max(1);
        self
    }
}

#[derive(Debug)]
pub enum HandlerEvent {
    Stream(InboundStream),
}

#[derive(Debug)]
pub(crate) enum InboundEvent {
    Data(Vec<u8>),
    Finished,
    Failed(crate::QlError),
}

pub(crate) struct OpenedStreamDelivery {
    pub stream_id: StreamId,
    pub response: async_channel::Receiver<InboundEvent>,
}

pub struct Runtime<P> {
    identity: QlIdentity,
    platform: P,
    config: RuntimeConfig,
    rx: async_channel::Receiver<command::RuntimeCommand>,
    tx: async_channel::WeakSender<command::RuntimeCommand>,
}

pub fn new_runtime<P>(
    identity: QlIdentity,
    platform: P,
    config: RuntimeConfig,
) -> (Runtime<P>, RuntimeHandle)
where
    P: QlPlatform,
{
    let config = config.normalized();
    let (tx, rx) = async_channel::unbounded();
    (
        Runtime {
            identity,
            platform,
            config,
            rx,
            tx: tx.downgrade(),
        },
        RuntimeHandle {
            tx,
            stream_send_buffer_bytes: config.stream_send_buffer_bytes,
        },
    )
}
