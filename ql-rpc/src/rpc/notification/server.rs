use std::future::Future;

use crate::{
    notification::Notification as NotificationRpc, rpc::read_eof_request, RouterConfig, RpcRead,
    RpcStream, RpcWrite, StreamCloseCode, StreamError,
};

#[trait_variant::make(NotificationHandler: Send)]
pub trait NotificationHandlerLocal<M, St>
where
    M: NotificationRpc,
    St: RpcStream,
{
    async fn handle(self, message: M::Payload);

    fn handle_transport_error(&self, _error: &St::Error) {}
}

pub(crate) async fn handle_notification_inner<S, M, St, H, HF, E>(
    state: S,
    config: RouterConfig,
    mut reader: St::Reader,
    writer: St::Writer,
    handle: H,
    handle_transport_error: E,
) where
    M: NotificationRpc + 'static,
    St: RpcStream + 'static,
    H: FnOnce(S, M::Payload) -> HF,
    HF: Future<Output = ()>,
    E: FnOnce(&S, &St::Error),
{
    let notification = match read_eof_request::<M::Payload, _>(&mut reader, config).await {
        Ok(notification) => notification,
        Err(error) => {
            let code = error.close_code();
            handle_transport_error(&state, &error);
            if let Some(code) = code {
                reader.close(code);
                writer.close(code);
            }
            return;
        }
    };

    writer.close(StreamCloseCode::CANCELLED);
    handle(state, notification).await;
}
