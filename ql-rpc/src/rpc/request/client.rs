use bytes::BufMut;

use crate::{read_bytes, request::Request, ChunkQueue, RpcCodec, RpcError, RpcRead};

pub fn encode_request<M: Request>(request: &M::Request, out: &mut (impl BufMut + AsMut<[u8]>)) {
    request.encode_value(out)
}

pub fn encode_response<M: Request>(response: &M::Response, out: &mut (impl BufMut + AsMut<[u8]>)) {
    response.encode_value(out)
}

pub async fn read_response<M, R>(mut reader: R) -> Result<M::Response, RpcError<M::Error, R::Error>>
where
    M: Request,
    R: RpcRead,
{
    let mut bytes = ChunkQueue::default();

    while let Some(chunk) = read_bytes(&mut reader, usize::MAX)
        .await
        .map_err(RpcError::Transport)?
    {
        bytes.push(chunk);
    }

    let value = M::Response::decode_value(&mut bytes).map_err(RpcError::Codec)?;
    if bytes.remaining() > 0 {
        return Err(crate::Error::TrailingBytes.into());
    }
    Ok(value)
}
