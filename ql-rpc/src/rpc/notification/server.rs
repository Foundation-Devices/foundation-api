use std::future::Future;

use ql_common::ResetCode;

use crate::{
    notification::Notification, rpc::read_eof_request, Context, RouterConfig, RpcCodec, RpcError,
    RpcRead, RpcStream, RpcWrite,
};

#[trait_variant::make(NotificationHandler: Send)]
pub trait NotificationHandlerLocal<M, St>
where
    M: Notification,
    St: RpcStream,
{
    async fn handle(self, context: Context, message: M::Payload);

    fn handle_error(&self, _error: &RpcError<M::Error, St::Error>) {}
}

pub(crate) fn handle_notification<S, Payload, Err, St, H, HF, E>(
    state: S,
    context: Context,
    config: RouterConfig,
    stream: St,
    handle: H,
    handle_error: E,
) -> impl Future<Output = ()>
where
    Payload: RpcCodec<Error = Err> + 'static,
    St: RpcStream + 'static,
    H: FnOnce(S, Context, Payload) -> HF,
    HF: Future<Output = ()>,
    E: FnOnce(&S, &RpcError<Err, St::Error>),
{
    let (mut reader, writer) = stream.split();

    async move {
        let notification = match read_eof_request::<Payload, _>(&mut reader, config).await {
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
        handle(state, context, notification).await;
    }
}
