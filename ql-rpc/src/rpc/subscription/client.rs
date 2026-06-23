use std::{
    future::poll_fn,
    task::{Context, Poll},
};

use crate::{
    subscription::{ReadStep, ResponseReader, Subscription},
    DropCloseRead, RpcError, RpcRead, StreamCloseCode,
};

pub struct SubscriptionCall<M, R>
where
    M: Subscription,
    R: RpcRead,
{
    stream: DropCloseRead<R>,
    reader: ResponseReader<M>,
}

impl<M, R> SubscriptionCall<M, R>
where
    M: Subscription,
    R: RpcRead,
{
    pub fn new(stream: R) -> Self {
        Self {
            stream: DropCloseRead::new(stream),
            reader: ResponseReader::default(),
        }
    }

    pub async fn next_event(&mut self) -> Option<Result<M::Event, RpcError<M::Error, R::Error>>> {
        poll_fn(|cx| self.poll_next_event(cx)).await
    }

    pub fn poll_next_event(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<M::Event, RpcError<M::Error, R::Error>>>> {
        if !self.stream.is_some() {
            return Poll::Ready(None);
        }

        loop {
            match self.reader.advance() {
                Ok(ReadStep::Item(value)) => return Poll::Ready(Some(Ok(value))),
                Ok(ReadStep::NeedMore) => {}
                Err(error) => {
                    self.stream.disarm();
                    return Poll::Ready(Some(Err(error)));
                }
            }

            match self.stream.poll_read(usize::MAX, cx) {
                Poll::Ready(Ok(Some(chunk))) => {
                    self.reader.push(chunk);
                }
                Poll::Ready(Ok(None)) => {
                    if self.reader.is_empty() {
                        self.stream.disarm();
                        return Poll::Ready(None);
                    }
                    self.stream.disarm();
                    return Poll::Ready(Some(Err(crate::Error::Truncated.into())));
                }
                Poll::Ready(Err(error)) => {
                    self.stream.disarm();
                    return Poll::Ready(Some(Err(RpcError::Transport(error))));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }

    pub fn close(mut self, code: StreamCloseCode) {
        self.close_inner(code);
    }

    fn close_inner(&mut self, code: StreamCloseCode) {
        DropCloseRead::close(&mut self.stream, code);
    }
}
