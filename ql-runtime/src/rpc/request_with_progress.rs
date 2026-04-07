use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures_lite::{future::poll_fn, Stream};
use ql_rpc::{
    request_with_progress::{ReadStep, RequestWithProgress},
    RpcError,
};

use super::RpcCallError;
use crate::ByteReader;

pub struct ProgressCall<M: RequestWithProgress> {
    pub(super) stream: ByteReader,
    pub(super) reader: Option<ql_rpc::request_with_progress::ResponseReader<M>>,
    pub(super) terminal: Option<Result<M::Response, RpcCallError<M::Error>>>,
}

impl<M> Unpin for ProgressCall<M> where M: RequestWithProgress {}

impl<M> ProgressCall<M>
where
    M: RequestWithProgress,
{
    pub async fn progress(&mut self) -> Option<M::Progress> {
        poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }
}

impl<M> Stream for ProgressCall<M>
where
    M: RequestWithProgress,
{
    type Item = M::Progress;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if this.terminal.is_some() || this.reader.is_none() {
            return Poll::Ready(None);
        }

        loop {
            let reader = this.reader.take().expect("progress reader is present");
            match reader.advance() {
                Ok(ReadStep::Progress { value, next }) => {
                    this.reader = Some(next);
                    return Poll::Ready(Some(value));
                }
                Ok(ReadStep::Response(response)) => {
                    this.terminal = Some(Ok(response));
                    return Poll::Ready(None);
                }
                Ok(ReadStep::NeedMore(next)) => {
                    this.reader = Some(next);
                }
                Err(error) => {
                    this.terminal = Some(Err(error.into()));
                    return Poll::Ready(None);
                }
            }

            match this.stream.poll_read_chunk(cx) {
                Poll::Ready(Ok(Some(chunk))) => {
                    let reader = this.reader.take().expect("progress reader is present");
                    this.reader = Some(reader.push(chunk));
                }
                Poll::Ready(Ok(None)) => {
                    this.reader = None;
                    this.terminal = Some(Err(RpcError::MissingResponse.into()));
                    return Poll::Ready(None);
                }
                Poll::Ready(Err(error)) => {
                    this.reader = None;
                    this.terminal = Some(Err(RpcCallError::Runtime(error.into())));
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<M> Future for ProgressCall<M>
where
    M: RequestWithProgress,
{
    type Output = Result<M::Response, RpcCallError<M::Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if let Some(result) = this.terminal.take() {
            return Poll::Ready(result);
        }

        loop {
            let Some(reader) = this.reader.take() else {
                panic!("progress call polled after completion");
            };

            match reader.advance() {
                Ok(ReadStep::Progress { next, .. }) => {
                    this.reader = Some(next);
                }
                Ok(ReadStep::Response(response)) => {
                    return Poll::Ready(Ok(response));
                }
                Ok(ReadStep::NeedMore(next)) => {
                    this.reader = Some(next);
                }
                Err(error) => return Poll::Ready(Err(error.into())),
            }

            match this.stream.poll_read_chunk(cx) {
                Poll::Ready(Ok(Some(chunk))) => {
                    let reader = this.reader.take().expect("progress reader is present");
                    this.reader = Some(reader.push(chunk));
                }
                Poll::Ready(Ok(None)) => {
                    this.reader = None;
                    return Poll::Ready(Err(RpcError::MissingResponse.into()));
                }
                Poll::Ready(Err(error)) => {
                    this.reader = None;
                    return Poll::Ready(Err(RpcCallError::Runtime(error.into())));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
