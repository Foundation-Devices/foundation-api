#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcError {
    Truncated,
    LengthOverflow,
    UnexpectedFrameKind(u8),
    MissingResponse,
    TrailingBytes,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated rpc payload"),
            Self::LengthOverflow => f.write_str("rpc payload length overflow"),
            Self::UnexpectedFrameKind(kind) => write!(f, "unexpected rpc frame kind {kind}"),
            Self::MissingResponse => f.write_str("missing terminal rpc response"),
            Self::TrailingBytes => f.write_str("trailing rpc bytes"),
        }
    }
}

impl std::error::Error for RpcError {}

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
