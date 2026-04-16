use std::{
    future::poll_fn,
    task::{Context, Poll},
};

use bytes::Bytes;
use ql_rpc::{
    download::{Download as DownloadRpc, ReadStep},
    Error,
};

use super::RpcError;
use crate::StreamReader;

pub struct DownloadCall<M: DownloadRpc> {
    pub(super) stream: StreamReader,
    pub(super) reader: Option<ql_rpc::download::ResponseHeaderReader<M>>,
}

impl<M> Unpin for DownloadCall<M> where M: DownloadRpc {}

impl<M> DownloadCall<M>
where
    M: DownloadRpc,
{
    pub async fn into_reader(
        mut self,
    ) -> Result<(M::ResponseHeader, DownloadReader), RpcError<M::Error>> {
        loop {
            let reader = self.reader.take().expect("download reader is present");
            match reader.advance()? {
                ReadStep::ResponseHeader { value, bytes } => {
                    return Ok((
                        value,
                        DownloadReader {
                            buffered: bytes,
                            stream: self.stream,
                        },
                    ));
                }
                ReadStep::NeedMore(next) => {
                    self.reader = Some(next);
                }
            }

            match poll_fn(|cx| self.stream.poll_read_chunk(cx)).await? {
                Some(chunk) => {
                    let reader = self.reader.take().expect("download reader is present");
                    self.reader = Some(reader.push(chunk));
                }
                None => return Err(Error::Truncated.into()),
            }
        }
    }
}

pub struct DownloadReader {
    buffered: ql_rpc::ChunkQueue,
    stream: StreamReader,
}

impl DownloadReader {
    pub fn poll_read(
        &mut self,
        max_len: usize,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, crate::QlStreamError>> {
        if let Some(chunk) = self.buffered.pop_front(max_len) {
            return Poll::Ready(Ok(Some(chunk)));
        }

        self.stream.poll_read(max_len, cx)
    }

    pub fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, crate::QlStreamError>> {
        self.poll_read(usize::MAX, cx)
    }

    pub async fn read(&mut self, max_len: usize) -> Result<Option<Bytes>, crate::QlStreamError> {
        poll_fn(|cx| self.poll_read(max_len, cx)).await
    }

    pub async fn read_chunk(&mut self) -> Result<Option<Bytes>, crate::QlStreamError> {
        self.read(usize::MAX).await
    }

    pub fn close(self, code: ql_wire::StreamCloseCode) {
        self.stream.close(code);
    }
}
