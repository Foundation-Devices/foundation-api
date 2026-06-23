use std::future::Future;

use crate::{
    notification::Notification as NotificationRpc, rpc::read_eof_request, ResetCode, RouterConfig,
    RpcError, RpcRead, RpcStream, RpcWrite,
};

#[trait_variant::make(NotificationHandler: Send)]
pub trait NotificationHandlerLocal<M, St>
where
    M: NotificationRpc,
    St: RpcStream,
{
    async fn handle(self, message: M::Payload);

    fn handle_error(&self, _error: &RpcError<M::Error, St::Error>) {}
}

pub(crate) async fn handle_notification_inner<S, M, St, H, HF, E>(
    state: S,
    config: RouterConfig,
    mut reader: St::Reader,
    writer: St::Writer,
    handle: H,
    handle_error: E,
) where
    M: NotificationRpc + 'static,
    St: RpcStream + 'static,
    H: FnOnce(S, M::Payload) -> HF,
    HF: Future<Output = ()>,
    E: FnOnce(&S, &RpcError<M::Error, St::Error>),
{
    let notification = match read_eof_request::<M::Payload, _>(&mut reader, config).await {
        Ok(notification) => notification,
        Err(error) => {
            let code = error.reset_code();
            handle_error(&state, &error);
            if let Some(code) = code {
                reader.reset(code);
                writer.reset(code);
            }
            return;
        }
    };

    writer.reset(ResetCode::CANCELLED);
    handle(state, notification).await;
}
