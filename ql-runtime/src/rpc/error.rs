use crate::QlError;

#[derive(Debug)]
pub enum RpcCallError<E> {
    Runtime(QlError),
    Rpc(ql_rpc::RpcError),
    Codec(E),
}

impl<E> From<QlError> for RpcCallError<E> {
    fn from(error: QlError) -> Self {
        Self::Runtime(error)
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
            Self::Runtime(error) => write!(f, "{error}"),
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
            Self::Runtime(error) => Some(error),
            Self::Rpc(error) => Some(error),
            Self::Codec(error) => Some(error),
        }
    }
}
