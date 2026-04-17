use crate::{RouteId, RpcCodec};

pub(crate) mod client;
pub(crate) mod codec;
pub(crate) mod server;

pub use client::ProgressCall;
pub use codec::{
    encode_progress, encode_request, encode_response, ReadStep, ResponseReader,
};
pub use server::{ProgressHandler, ProgressResponder};

pub trait Progress {
    const ROUTE: RouteId;
    type Error;
    type Request: RpcCodec<Error = Self::Error>;
    type Progress: RpcCodec<Error = Self::Error>;
    type Response: RpcCodec<Error = Self::Error>;
}
