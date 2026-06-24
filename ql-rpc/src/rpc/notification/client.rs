use crate::{notification::Notification, rpc::write_eof_value, ResetCode, RpcRead, RpcWrite};

pub async fn send<M, R, W>(reader: R, mut writer: W, payload: &M::Payload) -> Result<(), W::Error>
where
    M: Notification,
    R: RpcRead<Error = W::Error>,
    W: RpcWrite,
{
    reader.reset(ResetCode::CANCELLED);
    write_eof_value(&mut writer, payload).await
}
