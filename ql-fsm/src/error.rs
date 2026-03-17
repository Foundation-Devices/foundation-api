use ql_wire::WireError;
use thiserror::Error;

use crate::session::StreamError;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum QlFsmError {
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
}

impl From<WireError> for QlFsmError {
    fn from(value: WireError) -> Self {
        match value {
            WireError::InvalidPayload => Self::InvalidPayload,
            WireError::InvalidSignature => Self::InvalidSignature,
            WireError::Expired => Self::Expired,
            WireError::SigningFailed => Self::SigningFailed,
            WireError::EncryptFailed => Self::EncryptFailed,
            WireError::DecryptFailed => Self::DecryptFailed,
        }
    }
}

impl From<StreamError> for QlFsmError {
    fn from(value: StreamError) -> Self {
        match value {
            StreamError::MissingStream => Self::MissingStream,
            StreamError::NotWritable => Self::NotWritable,
            StreamError::SessionClosed => Self::SessionClosed,
        }
    }
}
