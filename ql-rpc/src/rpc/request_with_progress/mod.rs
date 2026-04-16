use crate::{RouteId, RpcCodec};

pub(crate) mod codec;

pub use codec::{
    encode_progress, encode_request, encode_response, ReadStep, ResponseReader,
};

pub trait RequestWithProgress {
    const ROUTE: RouteId;
    type Error;
    type Request: RpcCodec<Error = Self::Error>;
    type Progress: RpcCodec<Error = Self::Error>;
    type Response: RpcCodec<Error = Self::Error>;
}
