use bytes::BufMut;

use crate::{codec, RouteId, RpcCodec};

pub trait Request {
    const ROUTE: RouteId;
    type Error;
    type Request: RpcCodec<Error = Self::Error>;
    type Response: RpcCodec<Error = Self::Error>;
}

pub fn encode_request<M: Request>(request: &M::Request, out: &mut (impl BufMut + AsMut<[u8]>)) {
    codec::encode_value_part(request, out)
}

pub fn encode_response<M: Request>(response: &M::Response, out: &mut (impl BufMut + AsMut<[u8]>)) {
    codec::encode_value_part(response, out)
}
