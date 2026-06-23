use std::{
    future::{poll_fn, Future},
    pin::Pin,
    task::{Context, Poll},
};

use crate::{
    progress::{Progress, ReadStep, ResponseReader},
    DropCloseRead, Error, RpcError, RpcRead, StreamCloseCode,
};

pub struct ProgressCall<M, R>
where
    M: Progress,
    R: RpcRead,
{
    stream: DropCloseRead<R>,
    state: State<M, R::Error>,
}

enum State<M, T>
where
    M: Progress,
{
    Invalid,
    Reading(ResponseReader<M>),
    Terminal(Result<M::Response, RpcError<M::Error, T>>),
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
            stream: DropCloseRead::new(stream),
            state: State::Reading(ResponseReader::default()),
        }
    }

    pub async fn next_progress(&mut self) -> Option<M::Progress> {
        poll_fn(|cx| self.poll_next_progress(cx)).await
    }

    fn poll_step(&mut self, cx: &mut Context<'_>) -> Poll<Option<M::Progress>> {
        loop {
            let reader = match &mut self.state {
                State::Reading(reader) => reader,
                State::Terminal(_) | State::Done => return Poll::Ready(None),
                State::Invalid => panic!("invalid state"),
            };

            match reader.advance() {
                Ok(ReadStep::Progress(value)) => return Poll::Ready(Some(value)),
                Ok(ReadStep::Response(response)) => {
                    self.stream.disarm();
                    self.state = State::Terminal(Ok(response));
                    return Poll::Ready(None);
                }
                Ok(ReadStep::NeedMore) => {}
                Err(error) => {
                    self.stream.disarm();
                    self.state = State::Terminal(Err(error));
                    return Poll::Ready(None);
                }
            }

            match self.stream.poll_read(cx) {
                Poll::Ready(Ok(Some(chunk))) => {
                    let State::Reading(reader) = &mut self.state else {
                        panic!("invalid state");
                    };
                    reader.push(chunk);
                }
                Poll::Ready(Ok(None)) => {
                    self.stream.disarm();
                    self.state = State::Terminal(Err(Error::MissingResponse.into()));
                    return Poll::Ready(None);
                }
                Poll::Ready(Err(error)) => {
                    self.stream.disarm();
                    self.state = State::Terminal(Err(RpcError::Transport(error)));
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    pub fn poll_next_progress(&mut self, cx: &mut Context<'_>) -> Poll<Option<M::Progress>> {
        self.poll_step(cx)
    }

    pub fn close(mut self, code: StreamCloseCode) {
        self.close_inner(code);
    }

    fn close_inner(&mut self, code: StreamCloseCode) {
        self.state = State::Done;
        DropCloseRead::close(&mut self.stream, code);
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
                Poll::Ready(Some(_)) => {}
                Poll::Ready(None) => match std::mem::replace(&mut this.state, State::Invalid) {
                    State::Terminal(result) => {
                        this.state = State::Done;
                        return Poll::Ready(result);
                    }
                    State::Done => panic!("polled after completion"),
                    State::Invalid => panic!("polled during state transition"),
                    State::Reading(_) => {
                        panic!("progress call reached terminal step without result")
                    }
                },
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
