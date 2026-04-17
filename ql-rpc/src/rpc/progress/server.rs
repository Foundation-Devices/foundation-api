use std::marker::PhantomData;

use bytes::Bytes;

use crate::{
    RpcRead, RpcStream, RpcWrite, StreamCloseCode, StreamError, finish_bytes,
    progress::{Progress, encode_progress, encode_response},
    write_bytes,
};
use crate::{RouterConfig, rpc::read_framed_value};

pub trait ProgressHandler<M, St>
where
    M: Progress,
    St: RpcStream,
{
    fn handle(self, request: M::Request, responder: ProgressResponder<M, St::Writer>);

    fn handle_transport_error(&self, _error: &St::Error) {}
}

pub struct ProgressResponder<M, W>
where
    M: Progress,
    W: RpcWrite,
{
    writer: Option<W>,
    marker: PhantomData<fn() -> M>,
}

impl<M, W> ProgressResponder<M, W>
where
    M: Progress,
    W: RpcWrite,
{
    pub(crate) fn new(writer: W) -> Self {
        Self {
            writer: Some(writer),
            marker: PhantomData,
        }
    }

    pub async fn send(&mut self, progress: M::Progress) -> Result<(), W::Error> {
        let writer = self.writer.as_mut().expect("progress writer exists");
        let mut encoded = Vec::new();
        encode_progress::<M>(&progress, &mut encoded);
        write_bytes(writer, Bytes::from(encoded)).await
    }

    pub async fn finish(mut self, response: M::Response) -> Result<(), W::Error> {
        let mut writer = self.writer.take().expect("progress writer exists");
        let mut encoded = Vec::new();
        encode_response::<M>(&response, &mut encoded);
        write_bytes(&mut writer, Bytes::from(encoded)).await?;
        finish_bytes(&mut writer).await
    }

    pub fn close(mut self, code: StreamCloseCode) {
        if let Some(writer) = self.writer.take() {
            writer.close(code);
        }
    }
}

impl<M, W> Drop for ProgressResponder<M, W>
where
    M: Progress,
    W: RpcWrite,
{
    fn drop(&mut self) {
        if let Some(writer) = self.writer.take() {
            writer.close(StreamCloseCode::CANCELLED);
        }
    }
}

pub(crate) async fn handle_progress_inner<S, M, St>(
    state: S,
    config: RouterConfig,
    mut reader: St::Reader,
    writer: St::Writer,
) where
    M: Progress + 'static,
    S: ProgressHandler<M, St> + 'static,
    St: RpcStream + 'static,
{
    let request = match read_framed_value::<M::Request, _>(&mut reader, config).await {
        Ok(request) => request,
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

    state.handle(request, ProgressResponder::new(writer));
}
