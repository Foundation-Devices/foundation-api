use crate::{
    duplex::DuplexReceiver, rpc::write_eof_value, subscription::Subscription, RpcError, RpcStream,
};

pub type SubscriptionCall<M, R> = DuplexReceiver<<M as Subscription>::Event, R>;

pub async fn start<M, St>(
    stream: St,
    request: &M::Request,
) -> Result<SubscriptionCall<M, St::Reader>, RpcError<M::Error, St::Error>>
where
    M: Subscription,
    St: RpcStream,
{
    let (reader, mut writer) = stream.split();
    write_eof_value(&mut writer, request)
        .await
        .map_err(RpcError::Transport)?;
    Ok(DuplexReceiver::new(reader))
}
