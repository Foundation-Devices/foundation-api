use bytes::BufMut;

use crate::{codec, MethodId, ReadValueStep, RpcCodec, ValueReader};

pub trait Request {
    const METHOD: MethodId;
    type Error;
    type Request: RpcCodec<Error = Self::Error>;
    type Response: RpcCodec<Error = Self::Error>;
}

pub type RequestReader<M> = ValueReader<<M as Request>::Request>;
pub type RequestReadStep<M> = ReadValueStep<<M as Request>::Request>;
pub type ResponseReader<M> = ValueReader<<M as Request>::Response>;
pub type ResponseReadStep<M> = ReadValueStep<<M as Request>::Response>;

pub fn encode_request<M: Request>(
    request: &M::Request,
    out: &mut (impl BufMut + AsMut<[u8]>),
) -> Result<(), M::Error> {
    codec::encode_value_part(request, out)
}

pub fn encode_response<M: Request>(
    response: &M::Response,
    out: &mut (impl BufMut + AsMut<[u8]>),
) -> Result<(), M::Error> {
    codec::encode_value_part(response, out)
}
