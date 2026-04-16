use std::{
    future::poll_fn,
    marker::PhantomData,
    task::{Context, Poll},
};

use bytes::{BufMut, Bytes};

use crate::{codec, CallError, ChunkQueue, CodecError, RouteId, RpcCodec, RpcRead};

/// rpc where the responder streams a large byte body
/// the caller sends a request
/// the responder sends a typed header for the body
/// the responder streams the raw response bytes
pub trait Download {
    const ROUTE: RouteId;
    type Error;
    /// input needed to start the download
    type Request: RpcCodec<Error = Self::Error>;
    /// details about the body before bytes arrive
    type ResponseHeader: RpcCodec<Error = Self::Error>;
}

pub fn encode_request<M: Download>(request: &M::Request, out: &mut (impl BufMut + AsMut<[u8]>)) {
    codec::encode_value_part(request, out)
}

pub fn encode_response_header<M: Download>(
    response_header: &M::ResponseHeader,
    out: &mut (impl BufMut + AsMut<[u8]>),
) {
    codec::encode_value_part(response_header, out)
}

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

pub enum ReadStep<M: Download> {
    NeedMore(ResponseHeaderReader<M>),
    ResponseHeader {
        value: M::ResponseHeader,
        bytes: ChunkQueue,
    },
}

pub struct ResponseHeaderReader<M: Download> {
    bytes: codec::ChunkQueue,
    marker: PhantomData<fn() -> M>,
}

impl<M: Download> Default for ResponseHeaderReader<M> {
    fn default() -> Self {
        Self {
            bytes: codec::ChunkQueue::new(),
            marker: PhantomData,
        }
    }
}

impl<M: Download> ResponseHeaderReader<M> {
    pub fn push(mut self, chunk: Bytes) -> Self {
        self.bytes.push(chunk);
        self
    }

    pub fn advance(mut self) -> Result<ReadStep<M>, CodecError<M::Error>> {
        let Some(mut body) = self.bytes.try_take_part().map_err(CodecError::Rpc)? else {
            return Ok(ReadStep::NeedMore(self));
        };

        let value = {
            let value = M::ResponseHeader::decode_value(&mut body).map_err(CodecError::Codec)?;
            drop(body);
            value
        };

        Ok(ReadStep::ResponseHeader {
            value,
            bytes: self.bytes,
        })
    }
}
