use std::{
    future::poll_fn,
    marker::PhantomData,
    task::{Context, Poll},
};

use bytes::Bytes;
use ql_common::ResetCode;

use crate::{
    codec, duplex::Duplex, finish_bytes, write_bytes, ChunkQueue, DropResetRead, DropResetWrite,
    Error, RpcCodec, RpcError, RpcRead, RpcStream, RpcWrite,
};

pub fn start<M, St>(stream: St) -> DuplexCall<M, St::Writer, St::Reader>
where
    M: Duplex,
    St: RpcStream,
{
    let (reader, writer) = stream.split();
    DuplexCall {
        sender: DuplexSender::new(writer),
        receiver: DuplexReceiver::new(reader),
    }
}

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
    writer: DropResetWrite<W>,
    marker: PhantomData<fn() -> T>,
}

pub struct DuplexReceiver<T, R>
where
    T: RpcCodec,
    R: RpcRead,
{
    stream: DropResetRead<R>,
    reader: EventReader<T>,
}

impl<T, W> DuplexSender<T, W>
where
    T: RpcCodec,
    W: RpcWrite,
{
    pub fn new(writer: W) -> Self {
        Self {
            writer: DropResetWrite::new(writer),
            marker: PhantomData,
        }
    }

    pub async fn send(&mut self, event: &T) -> Result<(), W::Error> {
        let writer = &mut self.writer;
        let mut encoded = Vec::new();
        codec::encode_value_part(event, &mut encoded);
        write_bytes(writer, Bytes::from(encoded)).await
    }

    /// queue a graceful write-side finish and return without waiting for transport errors
    pub fn finish(mut self) {
        self.writer.queue_finish();
    }

    /// queue a graceful write-side finish and wait until the transport reports it was sent
    pub async fn finish_wait(mut self) -> Result<(), W::Error> {
        finish_bytes(&mut self.writer).await
    }

    pub fn reset(mut self, code: ResetCode) {
        DropResetWrite::reset(&mut self.writer, code);
    }
}

impl<T, R> DuplexReceiver<T, R>
where
    T: RpcCodec,
    R: RpcRead,
{
    pub fn new(stream: R) -> Self {
        Self {
            stream: DropResetRead::new(stream),
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
                    let code = error.reset_code().unwrap_or(ResetCode::DROPPED);
                    DropResetRead::reset(&mut self.stream, code);
                    return Poll::Ready(Some(Err(error)));
                }
            }

            match self.stream.poll_read(cx) {
                Poll::Ready(Ok(chunk)) if chunk.is_empty() => {
                    if self.reader.bytes.remaining() == 0 {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(Err(Error::Truncated.into())));
                }
                Poll::Ready(Ok(chunk)) => {
                    self.reader.push(chunk);
                }
                Poll::Ready(Err(error)) => {
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

enum ReadStep<T: RpcCodec> {
    NeedMore,
    Event(T),
}

struct EventReader<T: RpcCodec> {
    bytes: ChunkQueue,
    marker: PhantomData<fn() -> T>,
}

impl<T: RpcCodec> Default for EventReader<T> {
    fn default() -> Self {
        Self {
            bytes: ChunkQueue::default(),
            marker: PhantomData,
        }
    }
}

impl<T: RpcCodec> EventReader<T> {
    fn push(&mut self, chunk: Bytes) {
        self.bytes.push(chunk);
    }

    fn advance<E>(&mut self) -> Result<ReadStep<T>, RpcError<T::Error, E>> {
        let Some(mut body) = self.bytes.try_take_part().map_err(RpcError::Protocol)? else {
            return Ok(ReadStep::NeedMore);
        };

        let value = codec::decode_exact(&mut body)?;
        Ok(ReadStep::Event(value))
    }
}
