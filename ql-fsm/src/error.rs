use std::{
    error::Error,
    fmt::{Display, Formatter},
};

use ql_wire::{PairingId, WireError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveError {
    InvalidPayload,
    InvalidState,
    Expired,
    DecryptFailed,
    InvalidXid,
    NoSession,
    NotPairingMode,
    InvalidPairingId {
        expected: PairingId,
        actual: PairingId,
    },
    Replay,
}

impl Display for ReceiveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPayload => f.write_str("invalid payload"),
            Self::InvalidState => f.write_str("invalid state"),
            Self::Expired => f.write_str("expired"),
            Self::DecryptFailed => f.write_str("decryption failed"),
            Self::InvalidXid => f.write_str("invalid xid"),
            Self::NoSession => f.write_str("no active session"),
            Self::NotPairingMode => f.write_str("not in pairing mode"),
            Self::InvalidPairingId { expected, actual } => {
                write!(
                    f,
                    "invalid pairing id: expected {expected}, actual {actual}"
                )
            }
            Self::Replay => f.write_str("replay"),
        }
    }
}

impl std::error::Error for ReceiveError {}

impl From<WireError> for ReceiveError {
    fn from(value: WireError) -> Self {
        match value {
            WireError::InvalidPayload => Self::InvalidPayload,
            WireError::InvalidState => Self::InvalidState,
            WireError::Expired => Self::Expired,
            WireError::DecryptFailed => Self::DecryptFailed,
        }
    }
}

impl From<NoSessionError> for ReceiveError {
    fn from(_: NoSessionError) -> Self {
        Self::NoSession
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoPeerError;

impl Display for NoPeerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("no peer bound")
    }
}

impl Error for NoPeerError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoSessionError;

impl Display for NoSessionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "no session")
    }
}

impl Error for NoSessionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    MissingStream,
    NotWritable,
    NoSession,
}

impl Display for StreamError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::MissingStream => "missing stream",
            Self::NotWritable => "stream is not writable",
            Self::NoSession => "no session",
        };
        f.write_str(message)
    }
}

impl Error for StreamError {}

impl From<NoSessionError> for StreamError {
    fn from(_: NoSessionError) -> Self {
        Self::NoSession
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitReadError;

impl Display for CommitReadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid read commit")
    }
}

impl Error for CommitReadError {}
