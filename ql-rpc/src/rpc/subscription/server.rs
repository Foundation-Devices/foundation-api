use std::marker::PhantomData;

use bytes::Bytes;

use crate::{
    codec, finish_bytes, rpc::read_eof_request, subscription::Subscription as SubscriptionRpc,
    write_bytes, RouterConfig, RpcCodec, RpcRead, RpcStream, RpcWrite, StreamCloseCode,
    StreamError,
};

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
    pub(crate) fn new(writer: W) -> Self {
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

pub(crate) async fn handle_subscription_inner<S, M, St>(
    state: S,
    config: RouterConfig,
    mut reader: St::Reader,
    writer: St::Writer,
) where
    M: SubscriptionRpc + 'static,
    S: SubscriptionHandler<M, St> + 'static,
    St: RpcStream + 'static,
{
    let request = match read_eof_request::<M::Request, _>(&mut reader, config).await {
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
