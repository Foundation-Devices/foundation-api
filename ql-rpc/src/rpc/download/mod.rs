use crate::{RouteId, RpcCodec};

pub(crate) mod client;
pub(crate) mod codec;
pub(crate) mod server;

pub use client::{DownloadCall, DownloadReader};
pub use codec::{encode_request, encode_response_header, ReadStep, ResponseHeaderReader};
pub use server::{DownloadHandler, DownloadResponder, DownloadWriter};

/// rpc where the responder streams a large byte body
/// the caller sends a request
/// the responder sends a typed header for the body
/// the responder streams the raw response bytes
pub trait Download {
    const ROUTE: RouteId;
    type Error;
    /// input needed to start the download
    type Request: RpcCodec<Error = Self::Error>;
    /// details about the body before bytes arrive
    type ResponseHeader: RpcCodec<Error = Self::Error>;
}
