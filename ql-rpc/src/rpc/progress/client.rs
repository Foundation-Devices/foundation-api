use std::{
    future::{poll_fn, Future},
    pin::Pin,
    task::{Context, Poll},
};

use ql_common::ResetCode;

use crate::{
    progress::Progress,
    rpc::{
        progress::codec::{ReadStep, ResponseReader},
        write_eof_value,
    },
    DropResetRead, Error, RpcError, RpcRead, RpcStream,
};

pub async fn start<M, St>(
    stream: St,
    request: &M::Request,
) -> Result<ProgressCall<M, St::Reader>, RpcError<M::Error, St::Error>>
where
    M: Progress,
    St: RpcStream,
{
    let (reader, writer) = stream.split();
    write_eof_value(writer, request)
        .await
        .map_err(RpcError::Transport)?;
    Ok(ProgressCall::new(reader))
}

pub struct ProgressCall<M, R>
where
    M: Progress,
    R: RpcRead,
{
    stream: DropResetRead<R>,
    state: State<M, R::Error>,
}

enum State<M, T>
where
    M: Progress,
{
    Reading(ResponseReader<M>),
    AwaitingEof(M::Response),
    Terminal(Result<M::Response, RpcError<M::Error, T>>),
    Done,
}

enum PollStep<M, T>
where
    M: Progress,
{
    Terminal(Result<M::Response, RpcError<M::Error, T>>),
    Progress(M::Progress),
}

impl<M, R> Unpin for ProgressCall<M, R>
where
    M: Progress,
    R: RpcRead,
{
}

impl<M, R> ProgressCall<M, R>
where
    M: Progress,
    R: RpcRead,
{
    pub fn new(stream: R) -> Self {
        Self {
            stream: DropResetRead::new(stream),
            state: State::Reading(ResponseReader::default()),
        }
    }

    pub async fn next_progress(&mut self) -> Option<M::Progress> {
        poll_fn(|cx| self.poll_next_progress(cx)).await
    }

    fn poll_step(&mut self, cx: &mut Context<'_>) -> Poll<PollStep<M, R::Error>> {
        loop {
            let state = match std::mem::replace(&mut self.state, State::Done) {
                State::Reading(mut reader) => match reader.advance() {
                    Ok(ReadStep::Progress(value)) => {
                        self.state = State::Reading(reader);
                        return Poll::Ready(PollStep::Progress(value));
                    }
                    Ok(ReadStep::Response(response)) => State::AwaitingEof(response),
                    Ok(ReadStep::NeedMore) => State::Reading(reader),
                    Err(error) => {
                        let code = error.reset_code().unwrap_or(ResetCode::DROPPED);
                        DropResetRead::reset(&mut self.stream, code);
                        return Poll::Ready(PollStep::Terminal(Err(error)));
                    }
                },
                State::AwaitingEof(response) => State::AwaitingEof(response),
                State::Terminal(result) => return Poll::Ready(PollStep::Terminal(result)),
                State::Done => panic!("polled after completion"),
            };

            match self.stream.poll_read(cx) {
                Poll::Ready(Ok(chunk)) if chunk.is_empty() => {
                    let result = match state {
                        State::Reading(_) => Err(Error::Truncated.into()),
                        State::AwaitingEof(response) => Ok(response),
                        State::Terminal(_) | State::Done => unreachable!(),
                    };
                    return Poll::Ready(PollStep::Terminal(result));
                }
                Poll::Ready(Ok(chunk)) => match state {
                    State::Reading(mut reader) => {
                        reader.push(chunk);
                        self.state = State::Reading(reader);
                    }
                    State::AwaitingEof(_) => {
                        DropResetRead::reset(&mut self.stream, ResetCode::PROTOCOL);
                        return Poll::Ready(PollStep::Terminal(Err(Error::TrailingBytes.into())));
                    }
                    State::Terminal(_) | State::Done => unreachable!(),
                },
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(PollStep::Terminal(Err(RpcError::Transport(error))));
                }
                Poll::Pending => {
                    self.state = state;
                    return Poll::Pending;
                }
            }
        }
    }

    pub fn poll_next_progress(&mut self, cx: &mut Context<'_>) -> Poll<Option<M::Progress>> {
        if matches!(self.state, State::Terminal(_) | State::Done) {
            return Poll::Ready(None);
        }
        match self.poll_step(cx) {
            Poll::Ready(PollStep::Progress(value)) => Poll::Ready(Some(value)),
            Poll::Ready(PollStep::Terminal(result)) => {
                self.state = State::Terminal(result);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    pub fn reset(mut self, code: ResetCode) {
        self.reset_inner(code);
    }

    fn reset_inner(&mut self, code: ResetCode) {
        self.state = State::Done;
        DropResetRead::reset(&mut self.stream, code);
    }
}

impl<M, R> Future for ProgressCall<M, R>
where
    M: Progress,
    R: RpcRead,
{
    type Output = Result<M::Response, RpcError<M::Error, R::Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            match this.poll_step(cx) {
                // discard progress events
                Poll::Ready(PollStep::Progress(_)) => continue,
                Poll::Ready(PollStep::Terminal(result)) => return Poll::Ready(result),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
