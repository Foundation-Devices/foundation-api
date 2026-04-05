use ql_wire::WireError;

use crate::session::StreamError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QlFsmError {
    InvalidPayload,
    InvalidState,
    Expired,
    DecryptFailed,
    InvalidXid,
    MissingStream,
    NotWritable,
    InvalidRead,
    SessionClosed,
    NoPeerBound,
    NoSession,
}

impl std::fmt::Display for QlFsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidPayload => "invalid payload",
            Self::InvalidState => "invalid state",
            Self::Expired => "expired",
            Self::DecryptFailed => "decryption failed",
            Self::InvalidXid => "invalid xid",
            Self::MissingStream => "missing stream",
            Self::NotWritable => "stream is not writable",
            Self::InvalidRead => "invalid read commit",
            Self::SessionClosed => "session is closed",
            Self::NoPeerBound => "no peer bound",
            Self::NoSession => "no active session",
        };
        f.write_str(message)
    }
}

impl std::error::Error for QlFsmError {}

impl From<WireError> for QlFsmError {
    fn from(value: WireError) -> Self {
        match value {
            WireError::InvalidPayload => Self::InvalidPayload,
            WireError::InvalidState => Self::InvalidState,
            WireError::Expired => Self::Expired,
            WireError::DecryptFailed => Self::DecryptFailed,
        }
    }
}

impl From<StreamError> for QlFsmError {
    fn from(value: StreamError) -> Self {
        match value {
            StreamError::MissingStream => Self::MissingStream,
            StreamError::NotWritable => Self::NotWritable,
            StreamError::InvalidRead => Self::InvalidRead,
            StreamError::SessionClosed => Self::SessionClosed,
        }
    }
}
