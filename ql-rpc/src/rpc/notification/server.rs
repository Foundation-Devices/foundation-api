use crate::{
    notification::Notification as NotificationRpc, rpc::read_eof_request, RouterConfig, RpcRead,
    RpcStream, RpcWrite, StreamCloseCode, StreamError,
};

pub trait NotificationHandler<M, St>
where
    M: NotificationRpc,
    St: RpcStream,
{
    fn handle(self, message: M::Payload);

    fn handle_transport_error(&self, _error: &St::Error) {}
}

pub(crate) async fn handle_notification_inner<S, M, St>(
    state: S,
    config: RouterConfig,
    mut reader: St::Reader,
    writer: St::Writer,
) where
    M: NotificationRpc + 'static,
    S: NotificationHandler<M, St> + 'static,
    St: RpcStream + 'static,
{
    let notification = match read_eof_request::<M::Payload, _>(&mut reader, config).await {
        Ok(notification) => notification,
        Err(error) => {
            let code = error.close_code();
            state.handle_transport_error(&error);
            if let Some(code) = code {
                reader.close(code);
                writer.close(code);
            }
            return;
        }
    };

    writer.close(StreamCloseCode::CANCELLED);
    state.handle(notification);
}
