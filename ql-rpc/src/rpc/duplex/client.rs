use std::{
    future::poll_fn,
    marker::PhantomData,
    task::{Context, Poll},
};

use bytes::Bytes;

use crate::{
    duplex::{codec, Duplex, EventReader, ReadStep},
    finish_bytes, write_bytes, RpcCodec, RpcError, RpcRead, RpcWrite, StreamCloseCode,
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
    writer: Option<W>,
    marker: PhantomData<fn() -> T>,
}

pub struct DuplexReceiver<T, R>
where
    T: RpcCodec,
    R: RpcRead,
{
    stream: Option<R>,
    reader: EventReader<T>,
}

impl<T, W> DuplexSender<T, W>
where
    T: RpcCodec,
    W: RpcWrite,
{
    pub fn new(writer: W) -> Self {
        Self {
            writer: Some(writer),
            marker: PhantomData,
        }
    }

    pub async fn send(&mut self, event: &T) -> Result<(), W::Error> {
        let writer = self.writer.as_mut().unwrap();
        let mut encoded = Vec::new();
        codec::encode_event(event, &mut encoded);
        write_bytes(writer, Bytes::from(encoded)).await
    }

    pub async fn finish(mut self) -> Result<(), W::Error> {
        let mut writer = self.writer.take().unwrap();
        finish_bytes(&mut writer).await
    }

    pub fn close(mut self, code: StreamCloseCode) {
        if let Some(writer) = self.writer.take() {
            writer.close(code);
        }
    }
}

impl<T, W> Drop for DuplexSender<T, W>
where
    T: RpcCodec,
    W: RpcWrite,
{
    fn drop(&mut self) {
        if let Some(writer) = self.writer.take() {
            writer.close(StreamCloseCode::DROPPED);
        }
    }
}

impl<T, R> DuplexReceiver<T, R>
where
    T: RpcCodec,
    R: RpcRead,
{
    pub fn new(stream: R) -> Self {
        Self {
            stream: Some(stream),
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
        if self.stream.is_none() {
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

            let stream = self.stream.as_mut().unwrap();
            match stream.poll_read(usize::MAX, cx) {
                Poll::Ready(Ok(Some(chunk))) => {
                    self.reader.push(chunk);
                }
                Poll::Ready(Ok(None)) => {
                    if self.reader.is_empty() {
                        self.stream.take();
                        return Poll::Ready(None);
                    }
                    self.stream.take();
                    return Poll::Ready(Some(Err(crate::Error::Truncated.into())));
                }
                Poll::Ready(Err(error)) => {
                    self.stream.take();
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
        if let Some(stream) = self.stream.take() {
            stream.close(code);
        }
    }
}

impl<T, R> Drop for DuplexReceiver<T, R>
where
    T: RpcCodec,
    R: RpcRead,
{
    fn drop(&mut self) {
        if self.stream.is_some() {
            self.close_inner(StreamCloseCode::DROPPED);
        }
    }
}
