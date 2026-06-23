use crate::StreamCloseCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Truncated,
    LengthOverflow,
    UnexpectedFrameKind(u8),
    MissingResponse,
    TrailingBytes,
}

impl std::fmt::Display for Error {
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

impl std::error::Error for Error {}

impl Error {
    pub const fn close_code(self) -> StreamCloseCode {
        match self {
            Self::LengthOverflow => StreamCloseCode::LIMIT,
            Self::Truncated
            | Self::UnexpectedFrameKind(_)
            | Self::MissingResponse
            | Self::TrailingBytes => StreamCloseCode::REFUSED,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError<C, T> {
    Protocol(Error),
    Codec(C),
    Transport(T),
}

impl<C, T> RpcError<C, T> {
    pub const fn close_code(&self) -> Option<StreamCloseCode> {
        match self {
            Self::Protocol(error) => Some(error.close_code()),
            Self::Codec(_) => Some(StreamCloseCode::REFUSED),
            Self::Transport(_) => None,
        }
    }
}

impl<C, T> std::fmt::Display for RpcError<C, T>
where
    C: std::fmt::Display,
    T: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "{error}"),
            Self::Codec(error) => write!(f, "{error}"),
            Self::Transport(error) => write!(f, "{error}"),
        }
    }
}

impl<C, T> std::error::Error for RpcError<C, T>
where
    C: std::error::Error + 'static,
    T: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Codec(error) => Some(error),
            Self::Transport(error) => Some(error),
        }
    }
}

impl<C, T> From<Error> for RpcError<C, T> {
    fn from(error: Error) -> Self {
        Self::Protocol(error)
    }
}
