use std::marker::PhantomData;

use bytes::Bytes;

use super::{
    request::read_value_and_eof,
    stream::{finish_bytes, write_bytes, RpcRead, RpcStream, RpcWrite, StreamError},
    LocalMode, RouteMode, RouterConfig, SendMode,
};
use crate::{codec, subscription::Subscription as SubscriptionRpc, RpcCodec, StreamCloseCode};

pub trait SubscriptionHandler<M, St>
where
    M: SubscriptionRpc,
    St: RpcStream,
{
    fn handle(self, message: M::Request, responder: SubscriptionResponder<M::Event, St::Writer>);

    fn handle_transport_error(&self, _error: &St::Error) {}
}

pub struct SubscriptionResponder<T, W>
where
    W: RpcWrite,
{
    writer: Option<W>,
    marker: PhantomData<fn() -> T>,
}

impl<T, W> SubscriptionResponder<T, W>
where
    T: RpcCodec,
    W: RpcWrite,
{
    fn new(writer: W) -> Self {
        Self {
            writer: Some(writer),
            marker: PhantomData,
        }
    }

    pub async fn send(&mut self, event: T) -> Result<(), W::Error> {
        let writer = self.writer.as_mut().expect("subscription writer exists");
        let mut encoded = Vec::new();
        codec::encode_value_part(&event, &mut encoded);
        write_bytes(writer, Bytes::from(encoded)).await?;
        Ok(())
    }

    pub async fn finish(mut self) -> Result<(), W::Error> {
        let mut writer = self.writer.take().expect("subscription writer exists");
        finish_bytes(&mut writer).await
    }

    pub fn close(mut self, code: StreamCloseCode) {
        if let Some(writer) = self.writer.take() {
            writer.close(code);
        }
    }
}

impl<T, W> Drop for SubscriptionResponder<T, W>
where
    W: RpcWrite,
{
    fn drop(&mut self) {
        if let Some(writer) = self.writer.take() {
            writer.close(StreamCloseCode::CANCELLED);
        }
    }
}

#[doc(hidden)]
pub trait SubscriptionRouteMode<S, M, St>: RouteMode
where
    M: SubscriptionRpc + 'static,
    S: SubscriptionHandler<M, St> + 'static,
    St: RpcStream + 'static,
{
    fn handle_subscription(state: S, config: RouterConfig, stream: St) -> Self::RouteFuture;
}

impl<S, M, St> SubscriptionRouteMode<S, M, St> for LocalMode
where
    M: SubscriptionRpc + 'static,
    S: SubscriptionHandler<M, St> + 'static,
    St: RpcStream + 'static,
{
    fn handle_subscription(state: S, config: RouterConfig, stream: St) -> Self::RouteFuture {
        let (reader, writer) = stream.split();
        Box::pin(handle_subscription_inner::<S, M, St>(
            state, config, reader, writer,
        ))
    }
}

impl<S, M, St> SubscriptionRouteMode<S, M, St> for SendMode
where
    M: SubscriptionRpc + 'static,
    M::Request: Send + 'static,
    S: SubscriptionHandler<M, St> + Send + 'static,
    St: RpcStream + 'static,
    St::Reader: Send + 'static,
    St::Writer: Send + 'static,
{
    fn handle_subscription(state: S, config: RouterConfig, stream: St) -> Self::RouteFuture {
        let (reader, writer) = stream.split();
        Box::pin(handle_subscription_inner::<S, M, St>(
            state, config, reader, writer,
        ))
    }
}

async fn handle_subscription_inner<S, M, St>(
    state: S,
    config: RouterConfig,
    mut reader: St::Reader,
    writer: St::Writer,
) where
    M: SubscriptionRpc + 'static,
    S: SubscriptionHandler<M, St> + 'static,
    St: RpcStream + 'static,
{
    let request = match read_value_and_eof::<M::Request, _>(&mut reader, config).await {
        Ok(request) => request,
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

    state.handle(request, SubscriptionResponder::new(writer));
}
