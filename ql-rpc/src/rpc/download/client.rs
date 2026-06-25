use std::future::poll_fn;

use bytes::Bytes;
use ql_common::ResetCode;

use crate::{
    download::Download,
    parts::{PartFrameReader, PartReadStep},
    rpc::{parts::FrameKind, write_eof_value},
    DropResetRead, FramedPrefixStep, FramedReader, RpcError, RpcRead, RpcStream,
};

pub async fn start<M, St>(
    stream: St,
    request: &M::Request,
) -> Result<DownloadCall<M, St::Reader>, RpcError<M::Error, St::Error>>
where
    M: Download,
    St: RpcStream,
{
    let (reader, mut writer) = stream.split();
    write_eof_value(&mut writer, request)
        .await
        .map_err(RpcError::Transport)?;
    Ok(DownloadCall::new(reader))
}

pub struct DownloadCall<M, R>
where
    M: Download,
    R: RpcRead,
{
    stream: DropResetRead<R>,
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
    stream: DropResetRead<R>,
    reader: PartFrameReader<M::PartHeader>,
}

impl<M, R> DownloadCall<M, R>
where
    M: Download,
    R: RpcRead,
{
    pub fn new(stream: R) -> Self {
        Self {
            stream: DropResetRead::new(stream),
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
                    return Ok((
                        value,
                        DownloadReader {
                            stream: self.stream,
                            reader: PartFrameReader::<M::PartHeader>::new(bytes),
                        },
                    ));
                }
                Ok(FramedPrefixStep::NeedMore(next)) => next,
                Err(error) => return Err(error),
            };

            match poll_fn(|cx| self.stream.poll_read(cx)).await {
                Ok(Some(chunk)) => {
                    self.reader = Some(reader.push(chunk));
                }
                Ok(None) => return Err(crate::Error::Truncated.into()),
                Err(error) => return Err(RpcError::Transport(error)),
            }
        }
    }

    pub fn reset(mut self, code: ResetCode) {
        self.reset_inner(code);
    }

    fn reset_inner(&mut self, code: ResetCode) {
        DropResetRead::reset(&mut self.stream, code);
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
        if !self.stream.is_some() {
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
                self.stream.disarm();
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
                self.stream.disarm();
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

    pub fn reset(mut self, code: ResetCode) {
        self.reset_inner(code);
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

            match poll_fn(|cx| self.stream.poll_read(cx)).await {
                Ok(Some(chunk)) => {
                    self.reader.push(chunk);
                }
                Ok(None) => return Err(crate::Error::Truncated.into()),
                Err(error) => return Err(RpcError::Transport(error)),
            }
        }
    }

    fn reset_inner(&mut self, code: ResetCode) {
        DropResetRead::reset(&mut self.stream, code);
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

    pub fn reset(mut self, code: ResetCode) {
        self.parent.reset_inner(code);
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
            self.parent.reset_inner(ResetCode::DROPPED);
        }
    }
}
