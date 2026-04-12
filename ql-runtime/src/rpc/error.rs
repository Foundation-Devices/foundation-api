use ql_fsm::NoSessionError;

use crate::QlStreamError;

#[derive(Debug)]
pub enum RpcError<E> {
    NoSession,
    Closed(ql_rpc::StreamCloseCode),
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
            QlStreamError::StreamClosed { code } => Self::Closed(ql_rpc::StreamCloseCode(code.0)),
            QlStreamError::NoSession => Self::NoSession,
        }
    }
}

impl<E> From<ql_rpc::Error> for RpcError<E> {
    fn from(error: ql_rpc::Error) -> Self {
        Self::Protocol(error)
    }
}

impl<E> From<ql_rpc::CodecError<E>> for RpcError<E> {
    fn from(error: ql_rpc::CodecError<E>) -> Self {
        match error {
            ql_rpc::CodecError::Rpc(error) => Self::Protocol(error),
            ql_rpc::CodecError::Codec(error) => Self::Codec(error),
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
            Self::Closed(code) => write!(f, "stream closed {code:?}"),
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
            RpcError::Closed(_) => None,
        }
    }
}
