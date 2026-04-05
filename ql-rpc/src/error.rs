use ql_wire::StreamCloseCode;

use crate::MethodId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RpcError {
    #[error("truncated rpc payload")]
    Truncated,
    #[error("rpc payload length overflow")]
    LengthOverflow,
    #[error("invalid rpc version {0}")]
    InvalidVersion(u8),
    #[error("unexpected rpc method {actual:?}, expected {expected:?}")]
    UnexpectedMethod {
        expected: MethodId,
        actual: MethodId,
    },
    #[error("unexpected rpc frame kind {0}")]
    UnexpectedFrameKind(u8),
    #[error("missing terminal rpc response")]
    MissingResponse,
    #[error("trailing rpc bytes")]
    TrailingBytes,
}

impl RpcError {
    pub const fn close_code(self) -> StreamCloseCode {
        match self {
            Self::UnexpectedMethod { .. } => StreamCloseCode(404),
            Self::Truncated
            | Self::LengthOverflow
            | Self::InvalidVersion(_)
            | Self::UnexpectedFrameKind(_)
            | Self::MissingResponse
            | Self::TrailingBytes => StreamCloseCode(400),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcCodecError<E> {
    Rpc(RpcError),
    Codec(E),
}

impl<E> std::error::Error for RpcCodecError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RpcCodecError::Rpc(e) => Some(e),
            RpcCodecError::Codec(e) => Some(e),
        }
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.source()
    }
}

impl<E> std::fmt::Display for RpcCodecError<E>
where
    E: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcCodecError::Rpc(e) => write!(f, "{e}"),
            RpcCodecError::Codec(e) => write!(f, "{e}"),
        }
    }
}

impl<E> From<RpcError> for RpcCodecError<E> {
    fn from(error: RpcError) -> Self {
        Self::Rpc(error)
    }
}
