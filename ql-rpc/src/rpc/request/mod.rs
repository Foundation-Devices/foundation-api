use crate::{RouteId, RpcCodec};

pub(crate) mod client;
pub(crate) mod server;

pub use client::{encode_request, encode_response, read_response};
pub use server::{RequestHandler, Response};

/// request-response rpc with exactly one typed value in each direction
///
/// the request is read to eof on the server side, so callers must finish the
/// request stream after encoding [`Self::Request`]
/// the response is also read to eof and rejects trailing bytes after
/// [`Self::Response`]
pub trait Request {
    /// route used to dispatch this rpc family
    const ROUTE: RouteId;
    /// codec error shared by request and response values
    type Error;
    /// typed input sent by the caller
    type Request: RpcCodec<Error = Self::Error>;
    /// typed output returned by the responder
    type Response: RpcCodec<Error = Self::Error>;
}
