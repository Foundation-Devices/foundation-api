use crate::{RouteId, RpcCodec};

pub(crate) mod client;
pub(crate) mod codec;
pub(crate) mod server;

pub use client::{DownloadCall, DownloadReader};
pub use codec::{encode_request, encode_response_header, ReadStep, ResponseHeaderReader};
pub use server::{DownloadHandler, DownloadResponder, DownloadWriter};

/// rpc where the responder returns metadata first and raw bytes after that
///
/// the typed portion of the response ends at [`Self::ResponseHeader`]
/// after the header is decoded, the rest of the stream is exposed as raw byte
/// chunks through [`DownloadReader`]
pub trait Download {
    /// route used to dispatch this rpc family
    const ROUTE: RouteId;
    /// codec error shared by request and response header values
    type Error;
    /// typed input needed to start the download
    type Request: RpcCodec<Error = Self::Error>;
    /// typed metadata available before body bytes arrive
    type ResponseHeader: RpcCodec<Error = Self::Error>;
}
