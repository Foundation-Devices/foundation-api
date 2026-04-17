use crate::{RouteId, RpcCodec};

pub(crate) mod client;
pub(crate) mod server;

pub use client::{encode_request, UploadCall};
pub use server::{UploadHandler, UploadReader, UploadResponder};

/// rpc where the caller uploads raw bytes after a typed request
///
/// the typed request usually describes how the responder should interpret the
/// following byte stream
/// the request is length-delimited so raw upload bytes can follow immediately
/// once the upload reaches eof, the responder returns one typed
/// [`Self::Response`]
pub trait Upload {
    /// route used to dispatch this rpc family
    const ROUTE: RouteId;
    /// codec error shared by request and response values
    type Error;
    /// typed input needed before request body bytes arrive
    type Request: RpcCodec<Error = Self::Error>;
    /// typed terminal result after the upload body is fully read
    type Response: RpcCodec<Error = Self::Error>;
}
