use std::{
    future::{poll_fn, Future},
    task::{Context, Poll},
};

use bytes::Bytes;

use crate::{ResetCode, RouteId, ServiceId, StreamId, QID};

pub trait RpcStream {
    type Error;
    type Reader: RpcRead<Error = Self::Error>;
    type Writer: RpcWrite<Error = Self::Error>;

    fn qid(&self) -> QID;
    fn stream_id(&self) -> StreamId;
    fn service_id(&self) -> ServiceId;
    fn route_id(&self) -> RouteId;
    fn split(self) -> (Self::Reader, Self::Writer);
}

pub trait RpcRead {
    type Error;

    /// reads inbound bytes until eof or error
    fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, Self::Error>>;

    /// aborts the read side
    fn reset(self, code: ResetCode);
}

pub trait RpcWrite {
    type Error;

    /// writes outbound bytes before finish or reset
    fn poll_write(
        &mut self,
        bytes: &mut Bytes,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>>;

    /// queues a graceful write-side finish
    fn queue_finish(&mut self);

    /// waits for the queued finish to be delivered
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;

    /// aborts the write side before finish; must not replace a queued finish
    fn reset(self, code: ResetCode);
}

pub async fn read_bytes<R>(reader: &mut R) -> Result<Option<Bytes>, R::Error>
where
    R: RpcRead,
{
    poll_fn(|cx| reader.poll_read(cx)).await
}

pub async fn write_bytes<W>(writer: &mut W, bytes: Bytes) -> Result<(), W::Error>
where
    W: RpcWrite,
{
    let mut bytes = bytes;
    poll_fn(|cx| writer.poll_write(&mut bytes, cx)).await
}

pub fn finish_bytes<W>(writer: &mut W) -> impl Future<Output = Result<(), W::Error>> + '_
where
    W: RpcWrite,
{
    writer.queue_finish();
    poll_fn(|cx| writer.poll_finish(cx))
}

pub fn reset_stream<St>(stream: St, code: ResetCode)
where
    St: RpcStream,
{
    let (reader, writer) = stream.split();
    reader.reset(code);
    writer.reset(code);
}

pub(crate) use drop::*;
mod drop {
    use super::*;

    pub struct DropResetRead<R: RpcRead> {
        inner: Option<R>,
    }

    impl<R: RpcRead> DropResetRead<R> {
        pub fn new(reader: R) -> Self {
            Self {
                inner: Some(reader),
            }
        }

        #[inline]
        pub fn is_some(&self) -> bool {
            self.inner.is_some()
        }

        #[inline]
        pub fn disarm(&mut self) {
            self.inner.take();
        }

        #[inline]
        pub fn reset(&mut self, code: ResetCode) {
            if let Some(reader) = self.inner.take() {
                reader.reset(code);
            }
        }
    }

    impl<R: RpcRead> RpcRead for DropResetRead<R> {
        type Error = R::Error;

        #[track_caller]
        fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, Self::Error>> {
            self.inner.as_mut().unwrap().poll_read(cx)
        }

        fn reset(mut self, code: ResetCode) {
            Self::reset(&mut self, code);
        }
    }

    impl<R: RpcRead> Drop for DropResetRead<R> {
        fn drop(&mut self) {
            self.reset(ResetCode::DROPPED);
        }
    }

    pub struct DropResetWrite<W: RpcWrite> {
        inner: Option<W>,
    }

    impl<W: RpcWrite> DropResetWrite<W> {
        pub fn new(writer: W) -> Self {
            Self {
                inner: Some(writer),
            }
        }

        #[inline]
        pub fn reset(&mut self, code: ResetCode) {
            if let Some(writer) = self.inner.take() {
                writer.reset(code);
            }
        }
    }

    impl<W: RpcWrite> RpcWrite for DropResetWrite<W> {
        type Error = W::Error;

        #[track_caller]
        fn poll_write(
            &mut self,
            bytes: &mut Bytes,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.inner.as_mut().unwrap().poll_write(bytes, cx)
        }

        fn queue_finish(&mut self) {
            self.inner.as_mut().unwrap().queue_finish();
        }

        #[track_caller]
        fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.as_mut().unwrap().poll_finish(cx)
        }

        fn reset(mut self, code: ResetCode) {
            Self::reset(&mut self, code);
        }
    }

    impl<W: RpcWrite> Drop for DropResetWrite<W> {
        fn drop(&mut self) {
            self.reset(ResetCode::DROPPED)
        }
    }
}
