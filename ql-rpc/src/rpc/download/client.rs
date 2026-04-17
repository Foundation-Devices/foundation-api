use std::{
    future::poll_fn,
    task::{Context, Poll},
};

use bytes::Bytes;

use crate::{
    download::{Download, ReadStep, ResponseHeaderReader},
    CallError, ChunkQueue, RpcRead,
};

pub struct DownloadCall<M, R>
where
    M: Download,
    R: RpcRead,
{
    stream: R,
    reader: Option<ResponseHeaderReader<M>>,
}

pub struct DownloadReader<R>
where
    R: RpcRead,
{
    buffered: ChunkQueue,
    stream: R,
}

impl<M, R> DownloadCall<M, R>
where
    M: Download,
    R: RpcRead,
{
    pub fn new(stream: R) -> Self {
        Self {
            stream,
            reader: Some(ResponseHeaderReader::default()),
        }
    }

    pub async fn into_reader(
        mut self,
    ) -> Result<(M::ResponseHeader, DownloadReader<R>), CallError<M::Error, R::Error>> {
        loop {
            let reader = self.reader.take().expect("download reader is present");
            let reader = match reader.advance() {
                Ok(ReadStep::ResponseHeader { value, bytes }) => {
                    return Ok((
                        value,
                        DownloadReader {
                            buffered: bytes,
                            stream: self.stream,
                        },
                    ));
                }
                Ok(ReadStep::NeedMore(next)) => next,
                Err(error) => return Err(error.into()),
            };

            match poll_fn(|cx| self.stream.poll_read(usize::MAX, cx)).await {
                Ok(Some(chunk)) => {
                    self.reader = Some(reader.push(chunk));
                }
                Ok(None) => return Err(crate::Error::Truncated.into()),
                Err(error) => return Err(CallError::Transport(error)),
            }
        }
    }

    pub fn into_inner(self) -> R {
        self.stream
    }
}

impl<R> DownloadReader<R>
where
    R: RpcRead,
{
    pub fn poll_read(
        &mut self,
        max_len: usize,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, R::Error>> {
        if let Some(chunk) = self.buffered.pop_front(max_len) {
            return Poll::Ready(Ok(Some(chunk)));
        }

        self.stream.poll_read(max_len, cx)
    }

    pub fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, R::Error>> {
        self.poll_read(usize::MAX, cx)
    }

    pub async fn read(&mut self, max_len: usize) -> Result<Option<Bytes>, R::Error> {
        poll_fn(|cx| self.poll_read(max_len, cx)).await
    }

    pub async fn read_chunk(&mut self) -> Result<Option<Bytes>, R::Error> {
        self.read(usize::MAX).await
    }

    pub fn into_inner(self) -> R {
        self.stream
    }
}
