use ql_wire::StreamCloseCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QlStreamError {
    StreamClosed { code: StreamCloseCode },
    NoSession,
}

impl std::fmt::Display for QlStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StreamClosed { code } => write!(f, "stream closed {code:?}"),
            Self::NoSession => f.write_str("no session"),
        }
    }
}

impl std::error::Error for QlStreamError {}
