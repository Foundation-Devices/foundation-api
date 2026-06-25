use std::{
    error::Error,
    fmt::{Display, Formatter},
};

use ql_wire::{PairingId, WireError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveError {
    InvalidRecordHeader(WireError),
    InvalidRecordVersion,
    InvalidHandshakeRecord(WireError),
    InvalidSessionRecord(WireError),
    InvalidSessionPayload(WireError),
    InvalidIkHandshake(WireError),
    InvalidKkHandshake(WireError),
    InvalidXxHandshake(WireError),
    InvalidRemoteBundle,
    InvalidQid,
    NoPeer,
    NoSession,
    NotPairingMode,
    InvalidPairingId {
        expected: PairingId,
        actual: PairingId,
    },
}

impl Display for ReceiveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRecordHeader(error) => write!(f, "invalid record header: {error}"),
            Self::InvalidRecordVersion => f.write_str("invalid record version"),
            Self::InvalidHandshakeRecord(error) => {
                write!(f, "invalid handshake record: {error}")
            }
            Self::InvalidSessionRecord(error) => write!(f, "invalid session record: {error}"),
            Self::InvalidSessionPayload(error) => write!(f, "invalid session payload: {error}"),
            Self::InvalidIkHandshake(error) => write!(f, "invalid ik handshake: {error}"),
            Self::InvalidKkHandshake(error) => write!(f, "invalid kk handshake: {error}"),
            Self::InvalidXxHandshake(error) => write!(f, "invalid xx handshake: {error}"),
            Self::InvalidRemoteBundle => f.write_str("invalid remote bundle"),
            Self::InvalidQid => f.write_str("invalid qid"),
            Self::NoPeer => f.write_str("no bound peer"),
            Self::NoSession => f.write_str("no active session"),
            Self::NotPairingMode => f.write_str("not in pairing mode"),
            Self::InvalidPairingId { expected, actual } => {
                write!(
                    f,
                    "invalid pairing id: expected {expected}, actual {actual}"
                )
            }
        }
    }
}

impl std::error::Error for ReceiveError {}

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
    NoSession,
}

impl Display for StreamError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::MissingStream => "missing stream",
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
