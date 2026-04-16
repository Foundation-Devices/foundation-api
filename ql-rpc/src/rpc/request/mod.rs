use crate::{RouteId, RpcCodec};

pub(crate) mod client;
pub(crate) mod server;

pub use client::{encode_request, encode_response, read_response};
pub use server::{RequestHandler, Response};

pub trait Request {
    const ROUTE: RouteId;
    type Error;
    type Request: RpcCodec<Error = Self::Error>;
    type Response: RpcCodec<Error = Self::Error>;
}
