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

/// inbound byte stream for rpc protocols
///
/// dropping an active reader must reset it with `ResetCode::DROPPED`
///
/// a reader stops being active when:
///
/// - `poll_read` returns an empty chunk
/// - `poll_read` returns an error
/// - `reset` is called
///
/// afterward, `poll_read` must return an empty chunk.
pub trait RpcRead {
    type Error;

    /// reads inbound bytes. an empty chunk or error ends the read side
    fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bytes, Self::Error>>;

    /// resets the read side
    ///
    /// later calls to `poll_read` return an empty chunk
    fn reset(&mut self, code: ResetCode);
}

/// outbound byte stream for rpc protocols
///
/// dropping an active writer must reset it with `ResetCode::DROPPED`
///
/// a writer stops being active when:
///
/// - `finish` is called
/// - `poll_write` returns an error
/// - `reset` is called
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
    /// polling the future to completion is optional
    fn finish(self) -> Self::Finish;

    /// resets the write side
    ///
    /// later calls to `poll_write` or `finish` return an error
    fn reset(&mut self, code: ResetCode);
}

/// reads inbound bytes. an empty chunk or error ends the read side
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
