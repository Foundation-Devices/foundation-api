use std::{
    future::poll_fn,
    task::{Context, Poll},
};

use bytes::Bytes;

use crate::{RouteId, StreamCloseCode};

pub trait RpcStream {
    type Reader: RpcRead;
    type Writer: RpcWrite;

    fn route_id(&self) -> Option<RouteId>;
    fn split(self) -> (Self::Reader, Self::Writer);
}

pub trait RpcRead {
    fn poll_read(
        &mut self,
        max_len: usize,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamCloseCode>>;
    fn close(self, code: StreamCloseCode);
}

pub trait RpcWrite {
    fn poll_write(
        &mut self,
        bytes: &mut Bytes,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), StreamCloseCode>>;
    fn finish(self);
    fn close(self, code: StreamCloseCode);
}

pub async fn read_bytes<R>(reader: &mut R, max_len: usize) -> Result<Option<Bytes>, StreamCloseCode>
where
    R: RpcRead,
{
    poll_fn(|cx| reader.poll_read(max_len, cx)).await
}

pub async fn write_bytes<W>(writer: &mut W, bytes: Bytes) -> Result<(), StreamCloseCode>
where
    W: RpcWrite,
{
    let mut bytes = bytes;
    poll_fn(|cx| writer.poll_write(&mut bytes, cx)).await
}

pub fn close_stream<St>(stream: St, code: StreamCloseCode)
where
    St: RpcStream,
{
    let (reader, writer) = stream.split();
    reader.close(code);
    writer.close(code);
}
