use std::{
    future::poll_fn,
    task::{Context, Poll},
};

use crate::{CallError, RpcRead};
use crate::subscription::{ReadStep, ResponseReader, Subscription};

pub struct SubscriptionCall<M, R>
where
    M: Subscription,
    R: RpcRead,
{
    stream: R,
    reader: Option<ResponseReader<M>>,
}

impl<M, R> SubscriptionCall<M, R>
where
    M: Subscription,
    R: RpcRead,
{
    pub fn new(stream: R) -> Self {
        Self {
            stream,
            reader: Some(ResponseReader::default()),
        }
    }

    pub async fn next_event(&mut self) -> Option<Result<M::Event, CallError<M::Error, R::Error>>> {
        poll_fn(|cx| self.poll_next_event(cx)).await
    }

    pub fn poll_next_event(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<M::Event, CallError<M::Error, R::Error>>>> {
        loop {
            let Some(reader) = self.reader.take() else {
                return Poll::Ready(None);
            };

            let reader = match reader.advance() {
                Ok(ReadStep::Item { value, next }) => {
                    self.reader = Some(next);
                    return Poll::Ready(Some(Ok(value)));
                }
                Ok(ReadStep::NeedMore(next)) => next,
                Err(error) => return Poll::Ready(Some(Err(error.into()))),
            };

            match self.stream.poll_read(usize::MAX, cx) {
                Poll::Ready(Ok(Some(chunk))) => {
                    self.reader = Some(reader.push(chunk));
                }
                Poll::Ready(Ok(None)) => {
                    if reader.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(Err(crate::Error::Truncated.into())));
                }
                Poll::Ready(Err(error)) => {
                    self.reader = None;
                    return Poll::Ready(Some(Err(CallError::Transport(error))));
                }
                Poll::Pending => {
                    self.reader = Some(reader);
                    return Poll::Pending;
                }
            }
        }
    }

    pub fn into_inner(self) -> R {
        self.stream
    }
}
