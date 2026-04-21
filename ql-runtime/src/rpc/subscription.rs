use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures_lite::{future::poll_fn, Stream};
use ql_rpc::subscription::Subscription as SubscriptionRpc;

use super::RpcError;
use crate::StreamReader;

pub struct Subscription<M: SubscriptionRpc> {
    pub(super) inner: ql_rpc::subscription::SubscriptionCall<M, StreamReader>,
}

impl<M> Unpin for Subscription<M> where M: SubscriptionRpc {}

impl<M> Subscription<M>
where
    M: SubscriptionRpc,
{
    pub async fn next_event(&mut self) -> Option<Result<M::Event, RpcError<M::Error>>> {
        poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }
}

impl<M> Stream for Subscription<M>
where
    M: SubscriptionRpc,
{
    type Item = Result<M::Event, RpcError<M::Error>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut()
            .inner
            .poll_next_event(cx)
            .map(|item| item.map(|result| Ok(result?)))
    }
}
