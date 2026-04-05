pub use handle::{ByteReader, ByteWriter, InboundStream, OutboundStream, RuntimeHandle};
pub use ql_fsm::{PeerStatus, QlFsmConfig, QlFsmError, SessionWriteId};
pub use ql_wire::{
    self as wire, CloseTarget, PeerBundle, QlIdentity, SessionCloseCode, StreamCloseCode, StreamId,
    XID,
};

pub(crate) mod command;
pub(crate) mod driver;
pub mod handle;
pub mod platform;
#[cfg(feature = "rpc")]
pub mod rpc;

#[cfg(test)]
mod tests;

use thiserror::Error;

use self::platform::QlPlatform;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum QlError {
    #[error("invalid payload")]
    InvalidPayload,
    #[error("invalid state")]
    InvalidState,
    #[error("expired")]
    Expired,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("invalid xid")]
    InvalidXid,
    #[error("missing stream")]
    MissingStream,
    #[error("stream is not writable")]
    NotWritable,
    #[error("invalid read")]
    InvalidRead,
    #[error("session is closed")]
    SessionClosed,
    #[error("no peer bound")]
    NoPeerBound,
    #[error("no active session")]
    NoSession,
    #[error("send failed")]
    SendFailed,
    #[error("stream closed {code:?}")]
    StreamClosed {
        target: CloseTarget,
        code: StreamCloseCode,
    },
    #[error("cancelled")]
    Cancelled,
}

impl From<QlFsmError> for QlError {
    fn from(value: QlFsmError) -> Self {
        match value {
            QlFsmError::InvalidPayload => Self::InvalidPayload,
            QlFsmError::InvalidState => Self::InvalidState,
            QlFsmError::Expired => Self::Expired,
            QlFsmError::DecryptFailed => Self::DecryptFailed,
            QlFsmError::InvalidXid => Self::InvalidXid,
            QlFsmError::MissingStream => Self::MissingStream,
            QlFsmError::NotWritable => Self::NotWritable,
            QlFsmError::InvalidRead => Self::InvalidRead,
            QlFsmError::SessionClosed => Self::SessionClosed,
            QlFsmError::NoPeerBound => Self::NoPeerBound,
            QlFsmError::NoSession => Self::NoSession,
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

pub(crate) struct OpenedStreamDelivery {
    pub stream_id: StreamId,
    pub response: crate::ByteReader,
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
