use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures_lite::{future::poll_fn, Stream};
use ql_rpc::{
    subscription::{ReadStep, Subscription as SubscriptionRpc},
    RpcError,
};

use super::{ChunkState, RpcCallError};

pub struct Subscription<M: SubscriptionRpc> {
    pub(super) chunks: ChunkState,
    pub(super) reader: Option<ql_rpc::subscription::ResponseReader<M>>,
}

impl<M> Unpin for Subscription<M> where M: SubscriptionRpc {}

impl<M> Subscription<M>
where
    M: SubscriptionRpc,
{
    pub async fn next_event(&mut self) -> Option<Result<M::Event, RpcCallError<M::Error>>> {
        poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }
}

impl<M> Stream for Subscription<M>
where
    M: SubscriptionRpc,
{
    type Item = Result<M::Event, RpcCallError<M::Error>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            let Some(reader) = this.reader.take() else {
                return Poll::Ready(None);
            };

            match reader.advance() {
                Ok(ReadStep::Item { value, next }) => {
                    this.reader = Some(next);
                    return Poll::Ready(Some(Ok(value)));
                }
                Ok(ReadStep::End) => return Poll::Ready(None),
                Ok(ReadStep::NeedMore(next)) => {
                    this.reader = Some(next);
                }
                Err(error) => return Poll::Ready(Some(Err(error.into()))),
            }

            match this.chunks.poll_next(cx) {
                Poll::Ready(Ok(Some(chunk))) => {
                    let reader = this.reader.take().expect("subscription reader is present");
                    this.reader = Some(reader.push(&chunk));
                }
                Poll::Ready(Ok(None)) => {
                    this.reader = None;
                    return Poll::Ready(Some(Err(RpcError::Truncated.into())));
                }
                Poll::Ready(Err(error)) => {
                    this.reader = None;
                    return Poll::Ready(Some(Err(RpcCallError::Runtime(error))));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
