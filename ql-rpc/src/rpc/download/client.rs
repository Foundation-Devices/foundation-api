use std::marker::PhantomData;

use bytes::Bytes;
use ql_common::ResetCode;

use crate::{
    download::Download,
    parts::{PartFrame, PartFrameReader},
    read_bytes,
    rpc::{parts::FrameKind, read_framed_prefix, write_eof_value},
    DropResetRead, RpcError, RpcRead, RpcStream,
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
    marker: PhantomData<fn() -> M>,
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
            marker: PhantomData,
        }
    }

    pub async fn start(
        mut self,
    ) -> Result<(M::ResponseHeader, DownloadReader<M, R>), RpcError<M::Error, R::Error>> {
        let (value, bytes) = read_framed_prefix::<M::ResponseHeader, _>(&mut self.stream, None)
            .await
            .inspect_err(|error| {
                self.reset_inner(error.reset_code().unwrap_or(ResetCode::DROPPED));
            })?;
        Ok((
            value,
            DownloadReader {
                stream: self.stream,
                reader: PartFrameReader::<M::PartHeader>::new(bytes),
            },
        ))
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
        let Some(frame) = self.read_frame().await? else {
            return Ok(None);
        };

        let kind = match frame {
            PartFrame::PartHeader(value) => {
                return Ok(Some((
                    value,
                    DownloadPart {
                        parent: self,
                        finished: false,
                    },
                )));
            }
            PartFrame::BodyBytes(_) => FrameKind::BodyChunk,
            PartFrame::EndPart => FrameKind::EndPart,
        };

        self.reset_inner(ResetCode::PROTOCOL);
        Err(crate::Error::UnexpectedFrameKind(kind.tag()).into())
    }

    /// rejects any remaining part; an already terminal reader is accepted
    pub async fn complete(mut self) -> Result<(), RpcError<M::Error, R::Error>> {
        let Some(frame) = self.read_frame().await? else {
            return Ok(());
        };

        let kind = match frame {
            PartFrame::PartHeader(_) => FrameKind::PartHeader,
            PartFrame::BodyBytes(_) => FrameKind::BodyChunk,
            PartFrame::EndPart => FrameKind::EndPart,
        };

        self.reset_inner(ResetCode::PROTOCOL);
        Err(crate::Error::UnexpectedFrameKind(kind.tag()).into())
    }

    pub fn reset(mut self, code: ResetCode) {
        self.reset_inner(code);
    }

    async fn read_frame(
        &mut self,
    ) -> Result<Option<PartFrame<M::PartHeader>>, RpcError<M::Error, R::Error>> {
        if !self.stream.is_some() {
            return Ok(None);
        }

        loop {
            if let Some(frame) = self.reader.advance().inspect_err(|error| {
                self.reset_inner(error.reset_code().unwrap_or(ResetCode::DROPPED));
            })? {
                return Ok(Some(frame));
            }

            let chunk = read_bytes(&mut self.stream)
                .await
                .map_err(RpcError::Transport)?;
            if chunk.is_empty() {
                self.reader.finish()?;
                return Ok(None);
            }
            self.reader.push(chunk);
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
    /// reads part bytes, returning an empty chunk at the end of the part
    pub async fn read_chunk(&mut self) -> Result<Bytes, RpcError<M::Error, R::Error>> {
        if self.finished {
            return Ok(Bytes::new());
        }

        let frame = self
            .parent
            .read_frame()
            .await
            .inspect_err(|_| self.finished = true)?;
        match frame {
            Some(PartFrame::BodyBytes(bytes)) => Ok(bytes),
            Some(PartFrame::EndPart) => {
                self.finished = true;
                Ok(Bytes::new())
            }
            Some(PartFrame::PartHeader(_)) => {
                self.parent.reset_inner(ResetCode::PROTOCOL);
                self.finished = true;
                Err(crate::Error::UnexpectedFrameKind(FrameKind::PartHeader.tag()).into())
            }
            None => {
                self.finished = true;
                Err(crate::Error::Truncated.into())
            }
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
