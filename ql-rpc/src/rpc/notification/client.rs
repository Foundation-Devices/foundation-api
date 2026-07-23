use ql_common::ResetCode;

use crate::{notification::Notification, rpc::write_eof_value, RpcRead, RpcStream};

pub async fn send<M, St>(stream: St, payload: &M::Payload) -> Result<(), St::Error>
where
    M: Notification,
    St: RpcStream,
{
    let (reader, mut writer) = stream.split();
    reader.reset(ResetCode::CANCELLED);
    write_eof_value(&mut writer, payload).await
}
