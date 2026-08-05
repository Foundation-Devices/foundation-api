use std::{
    future::{poll_fn, Future},
    task::{Context, Poll},
};

use bytes::Bytes;
use ql_common::ResetCode;

pub trait RpcStream {
    type Error;
    type Reader: RpcRead<Error = Self::Error>;
    type Writer: RpcWrite<Error = Self::Error>;

    fn split(self) -> (Self::Reader, Self::Writer);
}

pub trait RpcRead {
    type Error;

    /// reads inbound bytes. an empty chunk or error is terminal
    fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bytes, Self::Error>>;

    /// aborts the read side
    fn reset(self, code: ResetCode);
}

pub trait RpcWrite {
    type Error;
    type Finish: Future<Output = Result<(), Self::Error>>;

    /// writes outbound bytes
    fn poll_write(
        &mut self,
        bytes: &mut Bytes,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>>;

    /// queues a graceful write-side finish and returns its delivery future
    ///
    /// polling the future to completion is considered OPTIONAL
    fn finish(self) -> Self::Finish;

    /// aborts the write side before finish
    fn reset(self, code: ResetCode);
}

/// reads inbound bytes. an empty chunk or error is terminal
pub async fn read_bytes<R>(reader: &mut R) -> Result<Bytes, R::Error>
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
        pub fn reset(&mut self, code: ResetCode) {
            if let Some(reader) = self.inner.take() {
                reader.reset(code);
            }
        }
    }

    impl<R: RpcRead> RpcRead for DropResetRead<R> {
        type Error = R::Error;

        #[track_caller]
        fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bytes, Self::Error>> {
            let result = self.inner.as_mut().unwrap().poll_read(cx);
            let terminal = match &result {
                Poll::Ready(Ok(bytes)) => bytes.is_empty(),
                Poll::Ready(Err(_)) => true,
                Poll::Pending => false,
            };
            if terminal {
                self.inner.take();
            }
            result
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
        type Finish = W::Finish;

        #[track_caller]
        fn poll_write(
            &mut self,
            bytes: &mut Bytes,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.inner.as_mut().unwrap().poll_write(bytes, cx)
        }

        fn finish(mut self) -> Self::Finish {
            self.inner.take().unwrap().finish()
        }

        fn reset(mut self, code: ResetCode) {
            Self::reset(&mut self, code);
        }
    }

    impl<W: RpcWrite> Drop for DropResetWrite<W> {
        fn drop(&mut self) {
            self.reset(ResetCode::DROPPED);
        }
    }
}
