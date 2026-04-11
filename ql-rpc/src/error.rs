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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError<E> {
    Rpc(Error),
    Codec(E),
}

impl<E> std::error::Error for CodecError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CodecError::Rpc(e) => Some(e),
            CodecError::Codec(e) => Some(e),
        }
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.source()
    }
}

impl<E> std::fmt::Display for CodecError<E>
where
    E: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::Rpc(e) => write!(f, "{e}"),
            CodecError::Codec(e) => write!(f, "{e}"),
        }
    }
}

impl<E> From<Error> for CodecError<E> {
    fn from(error: Error) -> Self {
        Self::Rpc(error)
    }
}
