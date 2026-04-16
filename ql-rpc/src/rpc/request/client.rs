use bytes::BufMut;

use crate::{request::Request, rpc::read_whole_value, CallError, RpcCodec, RpcRead};

pub fn encode_request<M: Request>(request: &M::Request, out: &mut (impl BufMut + AsMut<[u8]>)) {
    request.encode_value(out)
}

pub fn encode_response<M: Request>(
    response: &M::Response,
    out: &mut (impl BufMut + AsMut<[u8]>),
) {
    response.encode_value(out)
}

pub async fn read_response<M, R>(
    mut reader: R,
) -> Result<M::Response, CallError<M::Error, R::Error>>
where
    M: Request,
    R: RpcRead,
{
    read_whole_value::<M::Response, _>(&mut reader).await
}
