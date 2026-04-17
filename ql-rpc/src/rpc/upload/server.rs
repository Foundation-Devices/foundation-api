use std::{
    future::poll_fn,
    task::{Context, Poll},
};

use bytes::Bytes;

use crate::{
    request::Response, rpc::read_framed_request_prefix, ChunkQueue, RouterConfig, RpcRead,
    RpcStream, RpcWrite, StreamCloseCode, StreamError, Upload,
};

pub trait UploadHandler<M, St>
where
    M: Upload,
    St: RpcStream,
{
    fn handle(
        self,
        request: M::Request,
        upload: UploadReader<St::Reader>,
        responder: UploadResponder<M::Response, St::Writer>,
    );

    fn handle_transport_error(&self, _error: &St::Error) {}
}

pub struct UploadReader<R>
where
    R: RpcRead,
{
    buffered: ChunkQueue,
    stream: R,
}

pub struct UploadResponder<T, W>
where
    W: RpcWrite,
{
    inner: Response<T, W>,
}

impl<R> UploadReader<R>
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

impl<T, W> UploadResponder<T, W>
where
    T: crate::RpcCodec,
    W: RpcWrite,
{
    pub(crate) fn new(writer: W) -> Self {
        Self {
            inner: Response::new(writer),
        }
    }

    pub async fn respond(self, response: T) -> Result<(), W::Error> {
        self.inner.respond(response).await
    }

    pub fn close(self, code: StreamCloseCode) {
        self.inner.close(code);
    }
}

pub(crate) async fn handle_upload_inner<S, M, St>(
    state: S,
    config: RouterConfig,
    mut reader: St::Reader,
    writer: St::Writer,
) where
    M: Upload + 'static,
    S: UploadHandler<M, St> + 'static,
    St: RpcStream + 'static,
{
    let (request, buffered) = match read_framed_request_prefix::<M::Request, _>(&mut reader, config)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            let code = error.close_code();
            state.handle_transport_error(&error);
            if let Some(code) = code {
                reader.close(code);
                writer.close(code);
            }
            return;
        }
    };

    state.handle(
        request,
        UploadReader {
            buffered,
            stream: reader,
        },
        UploadResponder::new(writer),
    );
}
