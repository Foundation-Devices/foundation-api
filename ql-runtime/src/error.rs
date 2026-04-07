use ql_fsm::QlFsmError;
use ql_wire::StreamCloseCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QlError {
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
    SendFailed,
    StreamClosed { code: ql_wire::StreamCloseCode },
    Cancelled,
}

impl std::fmt::Display for QlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPayload => f.write_str("invalid payload"),
            Self::InvalidState => f.write_str("invalid state"),
            Self::Expired => f.write_str("expired"),
            Self::DecryptFailed => f.write_str("decryption failed"),
            Self::InvalidXid => f.write_str("invalid xid"),
            Self::MissingStream => f.write_str("missing stream"),
            Self::NotWritable => f.write_str("stream is not writable"),
            Self::InvalidRead => f.write_str("invalid read"),
            Self::SessionClosed => f.write_str("session is closed"),
            Self::NoPeerBound => f.write_str("no peer bound"),
            Self::NoSession => f.write_str("no active session"),
            Self::SendFailed => f.write_str("send failed"),
            Self::StreamClosed { code } => write!(f, "stream closed {code:?}"),
            Self::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl std::error::Error for QlError {}

impl From<QlStreamError> for QlError {
    fn from(value: QlStreamError) -> Self {
        match value {
            QlStreamError::StreamClosed { code } => Self::StreamClosed { code },
            QlStreamError::SessionClosed => Self::SessionClosed,
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QlStreamError {
    StreamClosed { code: StreamCloseCode },
    SessionClosed,
}

impl std::fmt::Display for QlStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StreamClosed { code } => write!(f, "stream closed {code:?}"),
            Self::SessionClosed => f.write_str("session is closed"),
        }
    }
}

impl std::error::Error for QlStreamError {}
