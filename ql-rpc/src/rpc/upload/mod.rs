use super::Route;
use crate::RpcCodec;

pub(crate) mod client;
pub(crate) mod server;

pub use client::{start, UploadCall, UploadPartWriter};
pub use server::{UploadHandler, UploadHandlerLocal, UploadPart, UploadReader, UploadResponder};

/// rpc where the caller uploads zero or more byte parts after a typed request
///
/// the typed request usually describes how the responder should interpret the
/// following parts
/// the request is length-delimited so raw upload bytes can follow immediately
/// once the upload reaches eof, the responder returns one typed
/// [`Self::Response`]
pub trait Upload: Route {
    /// codec error shared by request and response values
    type Error;
    /// typed input needed before request body bytes arrive
    type Request: RpcCodec<Error = Self::Error>;
    /// typed metadata available before each byte part arrives
    type PartHeader: RpcCodec<Error = Self::Error>;
    /// typed terminal result after the upload body is fully read
    type Response: RpcCodec<Error = Self::Error>;
}
