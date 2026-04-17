use std::{
    future::{poll_fn, Future},
    pin::Pin,
    task::{Context, Poll},
};

use crate::{
    progress::{Progress, ReadStep, ResponseReader},
    CallError, Error, RpcRead,
};

pub struct ProgressCall<M, R>
where
    M: Progress,
    R: RpcRead,
{
    stream: R,
    state: State<M, R::Error>,
}

enum State<M, T>
where
    M: Progress,
{
    Invalid,
    Reading(ResponseReader<M>),
    Terminal(Result<M::Response, CallError<M::Error, T>>),
    Done,
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
            stream,
            state: State::Reading(ResponseReader::default()),
        }
    }

    pub async fn next_progress(&mut self) -> Option<M::Progress> {
        poll_fn(|cx| self.poll_next_progress(cx)).await
    }

    pub fn poll_next_progress(&mut self, cx: &mut Context<'_>) -> Poll<Option<M::Progress>> {
        loop {
            let reader = match std::mem::replace(&mut self.state, State::Invalid) {
                State::Reading(reader) => reader,
                state @ (State::Terminal(_) | State::Done) => {
                    self.state = state;
                    return Poll::Ready(None);
                }
                State::Invalid => panic!("invalid state"),
            };

            match reader.advance() {
                Ok(ReadStep::Progress { value, next }) => {
                    self.state = State::Reading(next);
                    return Poll::Ready(Some(value));
                }
                Ok(ReadStep::Response(response)) => {
                    self.state = State::Terminal(Ok(response));
                    return Poll::Ready(None);
                }
                Ok(ReadStep::NeedMore(next)) => {
                    self.state = State::Reading(next);
                }
                Err(error) => {
                    self.state = State::Terminal(Err(error.into()));
                    return Poll::Ready(None);
                }
            }

            match self.stream.poll_read(usize::MAX, cx) {
                Poll::Ready(Ok(Some(chunk))) => {
                    let State::Reading(reader) = std::mem::replace(&mut self.state, State::Invalid)
                    else {
                        panic!("invalid state");
                    };
                    self.state = State::Reading(reader.push(chunk));
                }
                Poll::Ready(Ok(None)) => {
                    self.state = State::Terminal(Err(Error::MissingResponse.into()));
                    return Poll::Ready(None);
                }
                Poll::Ready(Err(error)) => {
                    self.state = State::Terminal(Err(CallError::Transport(error)));
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<M, R> Future for ProgressCall<M, R>
where
    M: Progress,
    R: RpcRead,
{
    type Output = Result<M::Response, CallError<M::Error, R::Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            let reader = match std::mem::replace(&mut this.state, State::Invalid) {
                State::Reading(reader) => reader,
                State::Terminal(result) => {
                    this.state = State::Done;
                    return Poll::Ready(result);
                }
                State::Done => panic!("polled after completion"),
                State::Invalid => panic!("polled during state transition"),
            };

            match reader.advance() {
                Ok(ReadStep::Progress { next, .. }) => {
                    this.state = State::Reading(next);
                }
                Ok(ReadStep::Response(response)) => {
                    this.state = State::Done;
                    return Poll::Ready(Ok(response));
                }
                Ok(ReadStep::NeedMore(next)) => {
                    this.state = State::Reading(next);
                }
                Err(error) => {
                    this.state = State::Done;
                    return Poll::Ready(Err(error.into()));
                }
            }

            match this.stream.poll_read(usize::MAX, cx) {
                Poll::Ready(Ok(Some(chunk))) => {
                    let State::Reading(reader) = std::mem::replace(&mut this.state, State::Invalid)
                    else {
                        panic!("progress reader is not present");
                    };
                    this.state = State::Reading(reader.push(chunk));
                }
                Poll::Ready(Ok(None)) => {
                    this.state = State::Done;
                    return Poll::Ready(Err(Error::MissingResponse.into()));
                }
                Poll::Ready(Err(error)) => {
                    this.state = State::Done;
                    return Poll::Ready(Err(CallError::Transport(error)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
