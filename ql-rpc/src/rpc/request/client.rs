use crate::{
    request::Request,
    rpc::{read_eof_value, write_eof_value},
    RpcError, RpcStream,
};

pub async fn call<M, St>(
    stream: St,
    request: &M::Request,
) -> Result<M::Response, RpcError<M::Error, St::Error>>
where
    M: Request,
    St: RpcStream,
{
    let (mut reader, mut writer) = stream.split();
    write_eof_value(&mut writer, request)
        .await
        .map_err(RpcError::Transport)?;
    read_eof_value::<M::Response, _>(&mut reader).await
}
