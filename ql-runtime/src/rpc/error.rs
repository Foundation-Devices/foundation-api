use ql_fsm::NoSessionError;
use ql_wire::StreamCloseCode;

use crate::QlStreamError;

#[derive(Debug)]
pub enum RpcCallError<E> {
    NoSession,
    StreamClosed(StreamCloseCode),
    Rpc(ql_rpc::RpcError),
    Codec(E),
}

impl<E> From<NoSessionError> for RpcCallError<E> {
    fn from(_: NoSessionError) -> Self {
        Self::NoSession
    }
}

impl<E> From<QlStreamError> for RpcCallError<E> {
    fn from(error: QlStreamError) -> Self {
        match error {
            QlStreamError::StreamClosed { code } => Self::StreamClosed(code),
            QlStreamError::NoSession => Self::NoSession,
        }
    }
}

impl<E> From<ql_rpc::RpcError> for RpcCallError<E> {
    fn from(error: ql_rpc::RpcError) -> Self {
        Self::Rpc(error)
    }
}

impl<E> From<ql_rpc::RpcCodecError<E>> for RpcCallError<E> {
    fn from(error: ql_rpc::RpcCodecError<E>) -> Self {
        match error {
            ql_rpc::RpcCodecError::Rpc(error) => Self::Rpc(error),
            ql_rpc::RpcCodecError::Codec(error) => Self::Codec(error),
        }
    }
}

impl<E> std::fmt::Display for RpcCallError<E>
where
    E: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSession => write!(f, "no session"),
            Self::StreamClosed(code) => write!(f, "stream closed {code:?}"),
            Self::Rpc(error) => write!(f, "{error}"),
            Self::Codec(error) => write!(f, "{error}"),
        }
    }
}

impl<E> std::error::Error for RpcCallError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rpc(error) => Some(error),
            Self::Codec(error) => Some(error),
            RpcCallError::NoSession => None,
            RpcCallError::StreamClosed(_) => None,
        }
    }
}
