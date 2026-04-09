use std::{
    error::Error,
    fmt::{Display, Formatter},
};

use ql_wire::WireError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveError {
    InvalidPayload,
    InvalidState,
    Expired,
    DecryptFailed,
    InvalidXid,
    NoSession,
}

impl Display for ReceiveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidPayload => "invalid payload",
            Self::InvalidState => "invalid state",
            Self::Expired => "expired",
            Self::DecryptFailed => "decryption failed",
            Self::InvalidXid => "invalid xid",
            Self::NoSession => "no active session",
        };
        f.write_str(message)
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
