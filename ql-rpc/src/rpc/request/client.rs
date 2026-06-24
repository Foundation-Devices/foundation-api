use crate::{
    request::Request,
    rpc::{read_eof_value, write_eof_value},
    RpcError, RpcRead, RpcWrite,
};

pub async fn call<M, R, W>(
    mut reader: R,
    mut writer: W,
    request: &M::Request,
) -> Result<M::Response, RpcError<M::Error, W::Error>>
where
    M: Request,
    R: RpcRead<Error = W::Error>,
    W: RpcWrite,
{
    write_eof_value(&mut writer, request)
        .await
        .map_err(RpcError::Transport)?;
    read_eof_value::<M::Response, _>(&mut reader).await
}
