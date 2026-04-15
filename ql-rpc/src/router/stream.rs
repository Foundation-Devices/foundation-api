use std::{
    future::poll_fn,
    task::{Context, Poll},
};

use bytes::Bytes;

use crate::{RouteId, StreamCloseCode};

pub trait RpcStream {
    type Error: StreamError;
    type Reader: RpcRead<Error = Self::Error>;
    type Writer: RpcWrite<Error = Self::Error>;

    fn route_id(&self) -> Option<RouteId>;
    fn split(self) -> (Self::Reader, Self::Writer);
}

pub trait RpcRead {
    type Error: StreamError;

    fn poll_read(
        &mut self,
        max_len: usize,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, Self::Error>>;
    fn close(self, code: StreamCloseCode);
}

pub trait RpcWrite {
    type Error: StreamError;

    fn poll_write(
        &mut self,
        bytes: &mut Bytes,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>>;
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
    fn close(self, code: StreamCloseCode);
}

pub trait StreamError: From<StreamCloseCode> {
    fn close_code(&self) -> Option<StreamCloseCode>;
}

impl StreamError for StreamCloseCode {
    fn close_code(&self) -> Option<StreamCloseCode> {
        Some(*self)
    }
}

pub async fn read_bytes<R>(reader: &mut R, max_len: usize) -> Result<Option<Bytes>, R::Error>
where
    R: RpcRead,
{
    poll_fn(|cx| reader.poll_read(max_len, cx)).await
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
