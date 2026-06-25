use std::future::{poll_fn, Future};

use bytes::Bytes;
use ql_common::ResetCode;

use crate::{
    request::Response,
    rpc::{
        parts::{FrameKind, PartFrameReader, PartReadStep},
        read_framed_request_prefix,
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

    fn handle_error(&self, _error: &RpcError<M::Error, St::Error>) {}
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

        match self.read_frame().await? {
            PartReadStep::PartHeader(value) => Ok(Some((
                value,
                UploadPart {
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

    async fn read_frame(
        &mut self,
    ) -> Result<PartReadStep<M::PartHeader>, crate::RpcError<M::Error, R::Error>> {
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
                Err(error) => return Err(crate::RpcError::Transport(error)),
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

impl<M, R> UploadPart<'_, M, R>
where
    M: Upload,
    R: RpcRead,
{
    pub async fn read_chunk(
        &mut self,
    ) -> Result<Option<Bytes>, crate::RpcError<M::Error, R::Error>> {
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

pub(crate) async fn handle_upload_inner<S, M, St, H, HF, E>(
    state: S,
    context: Context,
    config: RouterConfig,
    mut reader: St::Reader,
    writer: St::Writer,
    handle: H,
    handle_error: E,
) where
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
    let (request, buffered) =
        match read_framed_request_prefix::<M::Request, _>(&mut reader, config).await {
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
