use ql_fsm::NoSessionError;

use crate::QlStreamError;

#[derive(Debug)]
pub enum RpcError<E> {
    NoSession,
    Reset {
        code: ql_rpc::ResetCode,
        origin: ql_rpc::ResetOrigin,
    },
    Protocol(ql_rpc::Error),
    Codec(E),
}

impl<E> From<NoSessionError> for RpcError<E> {
    fn from(_: NoSessionError) -> Self {
        Self::NoSession
    }
}

impl<E> From<QlStreamError> for RpcError<E> {
    fn from(error: QlStreamError) -> Self {
        match error {
            QlStreamError::StreamReset { code, origin } => Self::Reset { code, origin },
            QlStreamError::NoSession => Self::NoSession,
        }
    }
}

impl<E> From<ql_rpc::Error> for RpcError<E> {
    fn from(error: ql_rpc::Error) -> Self {
        Self::Protocol(error)
    }
}

impl<E> From<ql_rpc::RpcError<E, QlStreamError>> for RpcError<E> {
    fn from(error: ql_rpc::RpcError<E, QlStreamError>) -> Self {
        match error {
            ql_rpc::RpcError::Protocol(error) => Self::Protocol(error),
            ql_rpc::RpcError::Codec(error) => Self::Codec(error),
            ql_rpc::RpcError::Transport(error) => error.into(),
        }
    }
}

impl<E> std::fmt::Display for RpcError<E>
where
    E: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSession => write!(f, "no session"),
            Self::Reset { code, origin } => write!(f, "stream reset {code:?} ({origin:?})"),
            Self::Protocol(error) => write!(f, "{error}"),
            Self::Codec(error) => write!(f, "{error}"),
        }
    }
}

impl<E> std::error::Error for RpcError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Codec(error) => Some(error),
            RpcError::NoSession => None,
            RpcError::Reset { .. } => None,
        }
    }
}
