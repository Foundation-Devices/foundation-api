use ql_common::ResetCode;
use ql_fsm::NoSessionError;

/// origin of a stream reset: either we triggered it locally or the peer sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResetOrigin {
    /// the reset code originated from the peer
    Peer,
    /// the reset code originated from local logic
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QlStreamError {
    StreamReset {
        code: ResetCode,
        origin: ResetOrigin,
    },
    NoSession,
}

impl std::fmt::Display for QlStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StreamReset { code, origin } => write!(f, "stream reset {code:?} ({origin:?})"),
            Self::NoSession => f.write_str("no session"),
        }
    }
}

impl std::error::Error for QlStreamError {}

impl From<NoSessionError> for QlStreamError {
    fn from(_: NoSessionError) -> Self {
        Self::NoSession
    }
}
