use std::marker::PhantomData;

use bytes::Bytes;

use crate::{
    codec, download::Download as DownloadRpc, finish_bytes, write_bytes, RpcCodec, RpcRead,
    RpcStream, RpcWrite, StreamCloseCode, StreamError,
};
use crate::{rpc::read_framed_value, RouterConfig};

pub trait DownloadHandler<M, St>
where
    M: DownloadRpc,
    St: RpcStream,
{
    fn handle(
        self,
        message: M::Request,
        responder: DownloadResponder<M::ResponseHeader, St::Writer>,
    );

    fn handle_transport_error(&self, _error: &St::Error) {}
}

pub struct DownloadResponder<T, W>
where
    W: RpcWrite,
{
    writer: Option<W>,
    marker: PhantomData<fn() -> T>,
}

pub struct DownloadWriter<W>
where
    W: RpcWrite,
{
    writer: Option<W>,
}

impl<T, W> DownloadResponder<T, W>
where
    T: RpcCodec,
    W: RpcWrite,
{
    pub(crate) fn new(writer: W) -> Self {
        Self {
            writer: Some(writer),
            marker: PhantomData,
        }
    }

    pub async fn respond(mut self, response_header: T) -> Result<DownloadWriter<W>, W::Error> {
        let mut writer = self.writer.take().expect("download writer exists");
        let mut encoded = Vec::new();
        codec::encode_value_part(&response_header, &mut encoded);
        write_bytes(&mut writer, Bytes::from(encoded)).await?;
        Ok(DownloadWriter {
            writer: Some(writer),
        })
    }

    pub fn close(mut self, code: StreamCloseCode) {
        if let Some(writer) = self.writer.take() {
            writer.close(code);
        }
    }
}

impl<T, W> Drop for DownloadResponder<T, W>
where
    W: RpcWrite,
{
    fn drop(&mut self) {
        if let Some(writer) = self.writer.take() {
            writer.close(StreamCloseCode::CANCELLED);
        }
    }
}

impl<W> DownloadWriter<W>
where
    W: RpcWrite,
{
    pub async fn send(&mut self, bytes: Bytes) -> Result<(), W::Error> {
        let writer = self.writer.as_mut().expect("download writer exists");
        write_bytes(writer, bytes).await
    }

    pub async fn finish(mut self) -> Result<(), W::Error> {
        let mut writer = self.writer.take().expect("download writer exists");
        finish_bytes(&mut writer).await
    }

    pub fn close(mut self, code: StreamCloseCode) {
        if let Some(writer) = self.writer.take() {
            writer.close(code);
        }
    }
}

impl<W> Drop for DownloadWriter<W>
where
    W: RpcWrite,
{
    fn drop(&mut self) {
        if let Some(writer) = self.writer.take() {
            writer.close(StreamCloseCode::CANCELLED);
        }
    }
}

pub(crate) async fn handle_download_inner<S, M, St>(
    state: S,
    config: RouterConfig,
    mut reader: St::Reader,
    writer: St::Writer,
) where
    M: DownloadRpc + 'static,
    S: DownloadHandler<M, St> + 'static,
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

    state.handle(request, DownloadResponder::new(writer));
}
