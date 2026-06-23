use std::future::poll_fn;

use bytes::{BufMut, Bytes};

use crate::{
    download::{Download, PartReadStep},
    rpc::parts::FrameKind,
    FramedPrefixStep, FramedReader, RpcCodec, RpcError, RpcRead, StreamCloseCode,
};

pub struct DownloadCall<M, R>
where
    M: Download,
    R: RpcRead,
{
    stream: Option<R>,
    reader: Option<FramedReader<M::ResponseHeader>>,
}

pub struct DownloadPart<'a, M, R>
where
    M: Download,
    R: RpcRead,
{
    parent: &'a mut DownloadReader<M, R>,
    finished: bool,
}

pub struct DownloadReader<M, R>
where
    M: Download,
    R: RpcRead,
{
    stream: Option<R>,
    reader: crate::download::PartFrameReader<M::PartHeader>,
}

impl<M, R> DownloadCall<M, R>
where
    M: Download,
    R: RpcRead,
{
    pub fn new(stream: R) -> Self {
        Self {
            stream: Some(stream),
            reader: Some(FramedReader::default()),
        }
    }

    pub async fn start(
        mut self,
    ) -> Result<(M::ResponseHeader, DownloadReader<M, R>), RpcError<M::Error, R::Error>> {
        loop {
            let reader = self.reader.take().unwrap();
            let reader = match reader.advance_prefix() {
                Ok(FramedPrefixStep::Value { value, bytes }) => {
                    let stream = self.stream.take().unwrap();
                    return Ok((
                        value,
                        DownloadReader {
                            stream: Some(stream),
                            reader: crate::download::PartFrameReader::<M::PartHeader>::new(bytes),
                        },
                    ));
                }
                Ok(FramedPrefixStep::NeedMore(next)) => next,
                Err(error) => return Err(error),
            };

            let stream = self.stream.as_mut().unwrap();
            match poll_fn(|cx| stream.poll_read(usize::MAX, cx)).await {
                Ok(Some(chunk)) => {
                    self.reader = Some(reader.push(chunk));
                }
                Ok(None) => return Err(crate::Error::Truncated.into()),
                Err(error) => return Err(RpcError::Transport(error)),
            }
        }
    }

    pub fn close(mut self, code: StreamCloseCode) {
        self.close_inner(code);
    }

    fn close_inner(&mut self, code: StreamCloseCode) {
        if let Some(stream) = self.stream.take() {
            stream.close(code);
        }
    }
}

impl<M, R> Drop for DownloadCall<M, R>
where
    M: Download,
    R: RpcRead,
{
    fn drop(&mut self) {
        self.close_inner(StreamCloseCode::DROPPED);
    }
}

impl<M, R> DownloadReader<M, R>
where
    M: Download,
    R: RpcRead,
{
    pub async fn next_part(
        &mut self,
    ) -> Result<Option<(M::PartHeader, DownloadPart<'_, M, R>)>, RpcError<M::Error, R::Error>> {
        if self.stream.is_none() {
            return Ok(None);
        }

        match self.read_frame().await? {
            PartReadStep::PartHeader(value) => Ok(Some((
                value,
                DownloadPart {
                    parent: self,
                    finished: false,
                },
            ))),
            PartReadStep::Finish => {
                self.stream.take();
                Ok(None)
            }
            PartReadStep::BodyBytes(_) => {
                Err(crate::Error::UnexpectedFrameKind(FrameKind::BodyChunk.tag()).into())
            }
            PartReadStep::EndPart => {
                Err(crate::Error::UnexpectedFrameKind(FrameKind::EndPart.tag()).into())
            }
            PartReadStep::NeedMore => unreachable!("read_frame waits for a complete frame"),
        }
    }

    pub async fn complete(mut self) -> Result<(), RpcError<M::Error, R::Error>> {
        match self.read_frame().await? {
            PartReadStep::Finish => {
                self.stream.take();
                Ok(())
            }
            PartReadStep::PartHeader(_) => {
                Err(crate::Error::UnexpectedFrameKind(FrameKind::PartHeader.tag()).into())
            }
            PartReadStep::BodyBytes(_) => {
                Err(crate::Error::UnexpectedFrameKind(FrameKind::BodyChunk.tag()).into())
            }
            PartReadStep::EndPart => {
                Err(crate::Error::UnexpectedFrameKind(FrameKind::EndPart.tag()).into())
            }
            PartReadStep::NeedMore => unreachable!("read_frame waits for a complete frame"),
        }
    }

    pub fn close(mut self, code: StreamCloseCode) {
        self.close_inner(code);
    }

    async fn read_frame(
        &mut self,
    ) -> Result<PartReadStep<M::PartHeader>, RpcError<M::Error, R::Error>> {
        loop {
            match self.reader.advance() {
                Ok(PartReadStep::NeedMore) => {}
                Ok(step) => return Ok(step),
                Err(error) => return Err(error),
            }

            let stream = self.stream.as_mut().unwrap();
            match poll_fn(|cx| stream.poll_read(usize::MAX, cx)).await {
                Ok(Some(chunk)) => {
                    self.reader.push(chunk);
                }
                Ok(None) => return Err(crate::Error::Truncated.into()),
                Err(error) => return Err(RpcError::Transport(error)),
            }
        }
    }

    fn close_inner(&mut self, code: StreamCloseCode) {
        if let Some(stream) = self.stream.take() {
            stream.close(code);
        }
    }
}

impl<M, R> Drop for DownloadReader<M, R>
where
    M: Download,
    R: RpcRead,
{
    fn drop(&mut self) {
        if self.stream.is_some() {
            self.close_inner(StreamCloseCode::DROPPED);
        }
    }
}

impl<M, R> DownloadPart<'_, M, R>
where
    M: Download,
    R: RpcRead,
{
    pub async fn read_chunk(&mut self) -> Result<Option<Bytes>, RpcError<M::Error, R::Error>> {
        if self.finished {
            return Ok(None);
        }

        match self.parent.read_frame().await? {
            PartReadStep::BodyBytes(bytes) => Ok(Some(bytes)),
            PartReadStep::EndPart => {
                self.finished = true;
                Ok(None)
            }
            PartReadStep::PartHeader(_) => {
                Err(crate::Error::UnexpectedFrameKind(FrameKind::PartHeader.tag()).into())
            }
            PartReadStep::Finish => {
                Err(crate::Error::UnexpectedFrameKind(FrameKind::Finish.tag()).into())
            }
            PartReadStep::NeedMore => unreachable!("read_frame waits for a complete frame"),
        }
    }

    pub fn close(mut self, code: StreamCloseCode) {
        self.parent.close_inner(code);
        self.finished = true;
    }
}

impl<M, R> Drop for DownloadPart<'_, M, R>
where
    M: Download,
    R: RpcRead,
{
    fn drop(&mut self) {
        if !self.finished {
            self.parent.close_inner(StreamCloseCode::DROPPED);
        }
    }
}

pub fn encode_request<M: Download>(request: &M::Request, out: &mut (impl BufMut + AsMut<[u8]>)) {
    request.encode_value(out)
}
