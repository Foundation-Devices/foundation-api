use crate::{RouteId, RpcCodec};

pub(crate) mod client;
pub(crate) mod codec;
pub(crate) mod server;

pub use client::ProgressCall;
pub use codec::{encode_progress, encode_request, encode_response, ReadStep, ResponseReader};
pub use server::{ProgressHandler, ProgressResponder};

/// rpc where the responder streams progress values before a final response
///
/// the request is length-delimited
/// response frames are tagged so the client can distinguish
/// [`Self::Progress`] items from the final [`Self::Response`]
/// reaching eof before the final response is an error
pub trait Progress {
    /// route used to dispatch this rpc family
    const ROUTE: RouteId;
    /// codec error shared by request, progress, and response values
    type Error;
    /// typed input sent by the caller
    type Request: RpcCodec<Error = Self::Error>;
    /// typed progress item emitted before completion
    type Progress: RpcCodec<Error = Self::Error>;
    /// typed terminal response that completes the call
    type Response: RpcCodec<Error = Self::Error>;
}
