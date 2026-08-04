use std::future::Future;

use bytes::Bytes;
use ql_common::ResetCode;

use crate::{
    read_bytes,
    request::Response,
    rpc::{
        parts::{FrameKind, PartFrame, PartFrameReader},
        read_framed_prefix,
    },
    Context, DropResetRead, RouterConfig, RpcError, RpcRead, RpcStream, RpcWrite, Upload,
};

#[trait_variant::make(UploadHandler: Send)]
pub trait UploadHandlerLocal<M, St>
where
    M: Upload,
    St: RpcStream,
{
    async fn handle(
        self,
        context: Context,
        request: M::Request,
        upload: UploadReader<M, St::Reader>,
        responder: UploadResponder<M::Response, St::Writer>,
    );

    fn handle_error(&self, error: &RpcError<M::Error, St::Error>) {
        let _ = error;
    }
}

pub struct UploadReader<M, R>
where
    M: Upload,
    R: RpcRead,
{
    stream: DropResetRead<R>,
    reader: PartFrameReader<M::PartHeader>,
}

pub struct UploadPart<'a, M, R>
where
    M: Upload,
    R: RpcRead,
{
    parent: &'a mut UploadReader<M, R>,
    finished: bool,
}

pub type UploadResponder<T, W> = Response<T, W>;

impl<M, R> UploadReader<M, R>
where
    M: Upload,
    R: RpcRead,
{
    pub async fn next_part(
        &mut self,
    ) -> Result<Option<(M::PartHeader, UploadPart<'_, M, R>)>, crate::RpcError<M::Error, R::Error>>
    {
        if !self.stream.is_some() {
            return Ok(None);
        }

        let Some(frame) = self.read_frame().await? else {
            return Ok(None);
        };

        let kind = match frame {
            PartFrame::PartHeader(value) => {
                return Ok(Some((
                    value,
                    UploadPart {
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

    async fn read_frame(
        &mut self,
    ) -> Result<Option<PartFrame<M::PartHeader>>, crate::RpcError<M::Error, R::Error>> {
        loop {
            if let Some(frame) = self.reader.advance().inspect_err(|error| {
                self.reset_inner(error.reset_code().unwrap_or(ResetCode::DROPPED));
            })? {
                return Ok(Some(frame));
            }

            let chunk = read_bytes(&mut self.stream)
                .await
                .map_err(crate::RpcError::Transport)?;
            if chunk.is_empty() {
                self.reader.finish()?;
                return Ok(None);
            }
            self.reader.push(chunk);
        }
    }

    pub fn reset(mut self, code: ResetCode) {
        self.reset_inner(code);
    }

    fn reset_inner(&mut self, code: ResetCode) {
        DropResetRead::reset(&mut self.stream, code);
    }
}

impl<M, R> UploadPart<'_, M, R>
where
    M: Upload,
    R: RpcRead,
{
    /// reads part bytes, returning an empty chunk at the end of the part
    pub async fn read_chunk(&mut self) -> Result<Bytes, crate::RpcError<M::Error, R::Error>> {
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

impl<M, R> Drop for UploadPart<'_, M, R>
where
    M: Upload,
    R: RpcRead,
{
    fn drop(&mut self) {
        if !self.finished {
            self.parent.reset_inner(ResetCode::DROPPED);
        }
    }
}

pub(crate) fn handle_upload<S, M, St, H, HF, E>(
    state: S,
    context: Context,
    config: RouterConfig,
    stream: St,
    handle: H,
    handle_error: E,
) -> impl Future<Output = ()>
where
    M: Upload + 'static,
    St: RpcStream + 'static,
    H: FnOnce(
        S,
        Context,
        M::Request,
        UploadReader<M, St::Reader>,
        UploadResponder<M::Response, St::Writer>,
    ) -> HF,
    HF: Future<Output = ()>,
    E: FnOnce(&S, &RpcError<M::Error, St::Error>),
{
    let (mut reader, writer) = stream.split();

    async move {
        let (request, buffered) =
            match read_framed_prefix::<M::Request, _>(&mut reader, Some(config.max_request_bytes))
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    let code = error.reset_code();
                    handle_error(&state, &error);
                    if let Some(code) = code {
                        reader.reset(code);
                        writer.reset(code);
                    }
                    return;
                }
            };

        handle(
            state,
            context,
            request,
            UploadReader {
                stream: DropResetRead::new(reader),
                reader: PartFrameReader::new(buffered),
            },
            Response::new(writer),
        )
        .await;
    }
}
