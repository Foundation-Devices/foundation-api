use std::{
    error::Error,
    fmt::{Display, Formatter},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveError {
    Wire {
        stage: ReceiveStage,
        source: ql_wire::Error,
    },
    InvalidRecordVersion,
    InvalidRemoteBundle,
    InvalidQid,
    NoPeer,
    NoSession,
    NotPairingMode,
    InvalidPairingId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveStage {
    RecordHeader,
    HandshakeRecord,
    SessionRecord,
    SessionPayload,
    IkHandshake,
    KkHandshake,
    XxHandshake,
}

impl ReceiveError {
    pub(crate) fn wire(stage: ReceiveStage, source: impl Into<ql_wire::Error>) -> Self {
        Self::Wire {
            stage,
            source: source.into(),
        }
    }
}

impl Display for ReceiveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wire { stage, source } => write!(f, "invalid {stage}: {source}"),
            Self::InvalidRecordVersion => f.write_str("invalid record version"),
            Self::InvalidRemoteBundle => f.write_str("invalid remote bundle"),
            Self::InvalidQid => f.write_str("invalid qid"),
            Self::NoPeer => f.write_str("no bound peer"),
            Self::NoSession => f.write_str("no active session"),
            Self::NotPairingMode => f.write_str("not in pairing mode"),
            Self::InvalidPairingId => f.write_str("invalid pairing id"),
        }
    }
}

impl Display for ReceiveStage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RecordHeader => f.write_str("record header"),
            Self::HandshakeRecord => f.write_str("handshake record"),
            Self::SessionRecord => f.write_str("session record"),
            Self::SessionPayload => f.write_str("session payload"),
            Self::IkHandshake => f.write_str("ik handshake"),
            Self::KkHandshake => f.write_str("kk handshake"),
            Self::XxHandshake => f.write_str("xx handshake"),
        }
    }
}

impl std::error::Error for ReceiveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Wire { source, .. } => Some(source),
            _ => None,
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
