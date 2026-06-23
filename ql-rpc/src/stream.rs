use std::{
    future::poll_fn,
    task::{Context, Poll},
};

use bytes::Bytes;

use crate::{RouteId, ServiceId, StreamCloseCode};

pub trait RpcStream {
    type Error;
    type Reader: RpcRead<Error = Self::Error>;
    type Writer: RpcWrite<Error = Self::Error>;

    fn service_id(&self) -> Option<ServiceId>;
    fn route_id(&self) -> Option<RouteId>;
    fn split(self) -> (Self::Reader, Self::Writer);
}

pub trait RpcRead {
    type Error;

    /// reads inbound bytes until eof or error
    fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, Self::Error>>;

    /// aborts the read side
    fn close(self, code: StreamCloseCode);
}

pub trait RpcWrite {
    type Error;

    /// writes outbound bytes before finish or close
    fn poll_write(
        &mut self,
        bytes: &mut Bytes,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>>;

    /// completes the write side and must be polled until ready without further write or close calls
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;

    /// aborts the write side before finish
    fn close(self, code: StreamCloseCode);
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

pub async fn finish_bytes<W>(writer: &mut W) -> Result<(), W::Error>
where
    W: RpcWrite,
{
    poll_fn(|cx| writer.poll_finish(cx)).await
}

pub fn close_stream<St>(stream: St, code: StreamCloseCode)
where
    St: RpcStream,
{
    let (reader, writer) = stream.split();
    reader.close(code);
    writer.close(code);
}

pub(crate) use drop::*;
mod drop {
    use super::*;

    pub struct DropCloseRead<R: RpcRead> {
        inner: Option<R>,
    }

    impl<R: RpcRead> DropCloseRead<R> {
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
        pub fn close(&mut self, code: StreamCloseCode) {
            if let Some(reader) = self.inner.take() {
                reader.close(code);
            }
        }
    }

    impl<R: RpcRead> RpcRead for DropCloseRead<R> {
        type Error = R::Error;

        #[track_caller]
        fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, Self::Error>> {
            self.inner.as_mut().unwrap().poll_read(cx)
        }

        fn close(mut self, code: StreamCloseCode) {
            Self::close(&mut self, code);
        }
    }

    impl<R: RpcRead> Drop for DropCloseRead<R> {
        fn drop(&mut self) {
            self.close(StreamCloseCode::DROPPED);
        }
    }

    pub struct DropCloseWrite<W: RpcWrite> {
        inner: Option<W>,
    }

    impl<W: RpcWrite> DropCloseWrite<W> {
        pub fn new(writer: W) -> Self {
            Self {
                inner: Some(writer),
            }
        }

        #[inline]
        pub fn close(&mut self, code: StreamCloseCode) {
            if let Some(writer) = self.inner.take() {
                writer.close(code);
            }
        }
    }

    impl<W: RpcWrite> RpcWrite for DropCloseWrite<W> {
        type Error = W::Error;

        #[track_caller]
        fn poll_write(
            &mut self,
            bytes: &mut Bytes,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.inner.as_mut().unwrap().poll_write(bytes, cx)
        }

        #[track_caller]
        fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.as_mut().unwrap().poll_finish(cx)
        }

        fn close(mut self, code: StreamCloseCode) {
            Self::close(&mut self, code);
        }
    }

    impl<W: RpcWrite> Drop for DropCloseWrite<W> {
        fn drop(&mut self) {
            self.close(StreamCloseCode::DROPPED)
        }
    }
}
