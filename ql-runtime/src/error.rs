use ql_wire::{ResetCode, ResetOrigin};

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
