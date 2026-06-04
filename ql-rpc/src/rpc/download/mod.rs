use super::Route;
use crate::RpcCodec;

pub(crate) mod client;
pub(crate) mod server;

pub use client::{encode_request, DownloadCall, DownloadPart, DownloadReader};
pub use server::{
    DownloadHandler, DownloadHandlerLocal, DownloadPartWriter, DownloadStart, DownloadWriter,
};

pub use crate::rpc::parts::{
    encode_body_chunk, encode_end_part, encode_finish, encode_part_header, PartFrameReader,
    PartReadStep,
};

/// rpc where the responder returns metadata first and then zero or more byte parts
///
/// the typed portion of the response ends at [`Self::ResponseHeader`]
/// after the header is decoded, the rest of the stream is exposed as typed
/// part headers followed by raw byte chunks through [`DownloadReader`]
pub trait Download: Route {
    /// codec error shared by request and response header values
    type Error;
    /// typed input needed to start the download
    type Request: RpcCodec<Error = Self::Error>;
    /// typed metadata available before parts arrive
    type ResponseHeader: RpcCodec<Error = Self::Error>;
    /// typed metadata available before each byte part arrives
    type PartHeader: RpcCodec<Error = Self::Error>;
}
