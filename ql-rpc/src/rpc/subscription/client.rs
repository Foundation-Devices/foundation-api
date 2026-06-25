use std::{
    future::poll_fn,
    task::{Context, Poll},
};

use ql_common::ResetCode;

use crate::{
    rpc::{
        subscription::codec::{ReadStep, ResponseReader},
        write_eof_value,
    },
    subscription::Subscription,
    DropResetRead, RpcError, RpcRead, RpcStream,
};

pub async fn start<M, St>(
    stream: St,
    request: &M::Request,
) -> Result<SubscriptionCall<M, St::Reader>, RpcError<M::Error, St::Error>>
where
    M: Subscription,
    St: RpcStream,
{
    let (reader, mut writer) = stream.split();
    write_eof_value(&mut writer, request)
        .await
        .map_err(RpcError::Transport)?;
    Ok(SubscriptionCall::new(reader))
}

pub struct SubscriptionCall<M, R>
where
    M: Subscription,
    R: RpcRead,
{
    stream: DropResetRead<R>,
    reader: ResponseReader<M>,
}

impl<M, R> SubscriptionCall<M, R>
where
    M: Subscription,
    R: RpcRead,
{
    pub fn new(stream: R) -> Self {
        Self {
            stream: DropResetRead::new(stream),
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

            match self.stream.poll_read(cx) {
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

    pub fn reset(mut self, code: ResetCode) {
        self.reset_inner(code);
    }

    fn reset_inner(&mut self, code: ResetCode) {
        DropResetRead::reset(&mut self.stream, code);
    }
}
