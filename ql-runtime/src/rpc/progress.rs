use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures_lite::Stream;
use ql_rpc::progress::Progress;

use super::RpcError;
use crate::StreamReader;

pub struct ProgressCall<M: Progress> {
    pub(super) inner: ql_rpc::progress::ProgressCall<M, StreamReader>,
}

impl<M> Unpin for ProgressCall<M> where M: Progress {}

impl<M> Stream for ProgressCall<M>
where
    M: Progress,
{
    type Item = M::Progress;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().inner.poll_next_progress(cx)
    }
}

impl<M> Future for ProgressCall<M>
where
    M: Progress,
{
    type Output = Result<M::Response, RpcError<M::Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().inner)
            .poll(cx)
            .map(|result| result.map_err(RpcError::from))
    }
}
