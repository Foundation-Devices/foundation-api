use std::{
    future::poll_fn,
    marker::PhantomData,
    task::{Context, Poll},
};

use bytes::Bytes;

use crate::{
    duplex::{codec, Duplex, EventReader, ReadStep},
    finish_bytes, write_bytes, DropCloseRead, DropCloseWrite, RpcCodec, RpcError, RpcRead,
    RpcWrite, StreamCloseCode,
};

pub struct DuplexCall<M, W, R>
where
    M: Duplex,
    W: RpcWrite,
    R: RpcRead,
{
    pub sender: DuplexSender<M::InitiatorEvent, W>,
    pub receiver: DuplexReceiver<M::ResponderEvent, R>,
}

pub struct DuplexSender<T, W>
where
    T: RpcCodec,
    W: RpcWrite,
{
    writer: DropCloseWrite<W>,
    marker: PhantomData<fn() -> T>,
}

pub struct DuplexReceiver<T, R>
where
    T: RpcCodec,
    R: RpcRead,
{
    stream: DropCloseRead<R>,
    reader: EventReader<T>,
}

impl<T, W> DuplexSender<T, W>
where
    T: RpcCodec,
    W: RpcWrite,
{
    pub fn new(writer: W) -> Self {
        Self {
            writer: DropCloseWrite::new(writer),
            marker: PhantomData,
        }
    }

    pub async fn send(&mut self, event: &T) -> Result<(), W::Error> {
        let writer = &mut self.writer;
        let mut encoded = Vec::new();
        codec::encode_event(event, &mut encoded);
        write_bytes(writer, Bytes::from(encoded)).await
    }

    pub async fn finish(mut self) -> Result<(), W::Error> {
        finish_bytes(&mut self.writer).await
    }

    pub fn close(mut self, code: StreamCloseCode) {
        DropCloseWrite::close(&mut self.writer, code);
    }
}

impl<T, R> DuplexReceiver<T, R>
where
    T: RpcCodec,
    R: RpcRead,
{
    pub fn new(stream: R) -> Self {
        Self {
            stream: DropCloseRead::new(stream),
            reader: EventReader::default(),
        }
    }

    pub async fn next_event(&mut self) -> Option<Result<T, RpcError<T::Error, R::Error>>> {
        poll_fn(|cx| self.poll_next_event(cx)).await
    }

    pub fn poll_next_event(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<T, RpcError<T::Error, R::Error>>>> {
        if !self.stream.is_some() {
            return Poll::Ready(None);
        }

        loop {
            match self.reader.advance() {
                Ok(ReadStep::Event(value)) => return Poll::Ready(Some(Ok(value))),
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

    pub fn close(mut self, code: StreamCloseCode) {
        self.close_inner(code);
    }

    fn close_inner(&mut self, code: StreamCloseCode) {
        DropCloseRead::close(&mut self.stream, code);
    }
}
