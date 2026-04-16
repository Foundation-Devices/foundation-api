use crate::{RouteId, RpcCodec};

/// rpc where the caller streams a large byte body
/// the caller sends a request
/// the caller streams the raw request bytes
/// the responder sends a final typed response
pub trait Upload {
    const ROUTE: RouteId;
    type Error;
    /// input needed to accept the upload
    type Request: RpcCodec<Error = Self::Error>;
    /// final status after all bytes are read
    type Response: RpcCodec<Error = Self::Error>;
}
