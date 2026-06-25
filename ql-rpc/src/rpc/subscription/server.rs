use std::{future::Future, marker::PhantomData};

use bytes::Bytes;
use ql_common::ResetCode;

use crate::{
    codec, finish_bytes, rpc::read_eof_request, subscription::Subscription, write_bytes, Context,
    DropResetWrite, RouterConfig, RpcCodec, RpcError, RpcRead, RpcStream, RpcWrite,
};

#[trait_variant::make(SubscriptionHandler: Send)]
pub trait SubscriptionHandlerLocal<M, St>
where
    M: Subscription,
    St: RpcStream,
{
    async fn handle(
        self,
        context: Context,
        message: M::Request,
        responder: SubscriptionResponder<M::Event, St::Writer>,
    );

    fn handle_error(&self, _error: &RpcError<M::Error, St::Error>) {}
}

pub struct SubscriptionResponder<T, W>
where
    W: RpcWrite,
{
    writer: DropResetWrite<W>,
    marker: PhantomData<fn() -> T>,
}

impl<T, W> SubscriptionResponder<T, W>
where
    T: RpcCodec,
    W: RpcWrite,
{
    pub(crate) fn new(writer: W) -> Self {
        Self {
            writer: DropResetWrite::new(writer),
            marker: PhantomData,
        }
    }

    pub async fn send(&mut self, event: T) -> Result<(), W::Error> {
        let writer = &mut self.writer;
        let mut encoded = Vec::new();
        codec::encode_value_part(&event, &mut encoded);
        write_bytes(writer, Bytes::from(encoded)).await?;
        Ok(())
    }

    pub async fn finish(mut self) -> Result<(), W::Error> {
        finish_bytes(&mut self.writer).await
    }

    pub fn reset(mut self, code: ResetCode) {
        DropResetWrite::reset(&mut self.writer, code);
    }
}

pub(crate) fn handle_subscription<S, Req, Event, Err, St, H, HF, E>(
    state: S,
    context: Context,
    config: RouterConfig,
    stream: St,
    handle: H,
    handle_error: E,
) -> impl Future<Output = ()>
where
    Req: RpcCodec<Error = Err> + 'static,
    Event: RpcCodec<Error = Err> + 'static,
    St: RpcStream + 'static,
    H: FnOnce(S, Context, Req, SubscriptionResponder<Event, St::Writer>) -> HF,
    HF: Future<Output = ()>,
    E: FnOnce(&S, &RpcError<Err, St::Error>),
{
    let (mut reader, writer) = stream.split();

    async move {
        let request = match read_eof_request::<Req, _>(&mut reader, config).await {
            Ok(request) => request,
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

        handle(state, context, request, SubscriptionResponder::new(writer)).await;
    }
}
