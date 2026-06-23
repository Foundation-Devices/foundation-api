use std::{future::Future, marker::PhantomData};

use bytes::Bytes;

use crate::{
    codec,
    download::Download as DownloadRpc,
    finish_bytes,
    rpc::{
        parts::{encode_body_chunk, encode_end_part, encode_finish, encode_part_header},
        read_eof_request,
    },
    write_bytes, RouterConfig, RpcError, RpcRead, RpcStream, RpcWrite, StreamCloseCode,
};

#[trait_variant::make(DownloadHandler: Send)]
pub trait DownloadHandlerLocal<M, St>
where
    M: DownloadRpc,
    St: RpcStream,
{
    async fn handle(self, message: M::Request, download: DownloadStart<M, St::Writer>);

    fn handle_error(&self, _error: &RpcError<M::Error, St::Error>) {}
}

pub struct DownloadStart<M, W>
where
    M: DownloadRpc,
    W: RpcWrite,
{
    writer: Option<W>,
    marker: PhantomData<fn() -> M>,
}

pub struct DownloadWriter<M, W>
where
    M: DownloadRpc,
    W: RpcWrite,
{
    writer: Option<W>,
    marker: PhantomData<fn() -> M>,
}

pub struct DownloadPartWriter<'a, M, W>
where
    M: DownloadRpc,
    W: RpcWrite,
{
    parent: &'a mut DownloadWriter<M, W>,
    finished: bool,
}

impl<M, W> DownloadStart<M, W>
where
    M: DownloadRpc,
    W: RpcWrite,
{
    pub(crate) fn new(writer: W) -> Self {
        Self {
            writer: Some(writer),
            marker: PhantomData,
        }
    }

    /// send the response header and begin streaming parts
    pub async fn start(
        mut self,
        response_header: M::ResponseHeader,
    ) -> Result<DownloadWriter<M, W>, W::Error> {
        let mut writer = self.writer.take().unwrap();
        let mut encoded = Vec::new();
        codec::encode_value_part(&response_header, &mut encoded);
        write_bytes(&mut writer, Bytes::from(encoded)).await?;
        Ok(DownloadWriter {
            writer: Some(writer),
            marker: PhantomData,
        })
    }

    /// send a header-only response and finish the stream
    pub async fn complete(mut self, response_header: M::ResponseHeader) -> Result<(), W::Error> {
        let mut writer = self.writer.take().unwrap();
        let mut encoded = Vec::new();
        codec::encode_value_part(&response_header, &mut encoded);
        encode_finish(&mut encoded);
        write_bytes(&mut writer, Bytes::from(encoded)).await?;
        finish_bytes(&mut writer).await
    }

    /// close the stream with a transport code
    pub fn close(mut self, code: StreamCloseCode) {
        if let Some(writer) = self.writer.take() {
            writer.close(code);
        }
    }
}

impl<M, W> Drop for DownloadStart<M, W>
where
    M: DownloadRpc,
    W: RpcWrite,
{
    fn drop(&mut self) {
        if let Some(writer) = self.writer.take() {
            writer.close(StreamCloseCode::DROPPED);
        }
    }
}

impl<M, W> DownloadWriter<M, W>
where
    M: DownloadRpc,
    W: RpcWrite,
{
    pub async fn start_part(
        &mut self,
        part_header: M::PartHeader,
    ) -> Result<DownloadPartWriter<'_, M, W>, W::Error> {
        let writer = self.writer.as_mut().unwrap();
        let mut encoded = Vec::new();
        encode_part_header(&part_header, &mut encoded);
        write_bytes(writer, Bytes::from(encoded)).await?;
        Ok(DownloadPartWriter {
            parent: self,
            finished: false,
        })
    }

    pub async fn finish(mut self) -> Result<(), W::Error> {
        let mut writer = self.writer.take().unwrap();
        let mut encoded = Vec::new();
        encode_finish(&mut encoded);
        write_bytes(&mut writer, Bytes::from(encoded)).await?;
        finish_bytes(&mut writer).await
    }

    pub fn close(mut self, code: StreamCloseCode) {
        if let Some(writer) = self.writer.take() {
            writer.close(code);
        }
    }
}

impl<M, W> Drop for DownloadWriter<M, W>
where
    M: DownloadRpc,
    W: RpcWrite,
{
    fn drop(&mut self) {
        if let Some(writer) = self.writer.take() {
            writer.close(StreamCloseCode::DROPPED);
        }
    }
}

impl<M, W> DownloadPartWriter<'_, M, W>
where
    M: DownloadRpc,
    W: RpcWrite,
{
    pub async fn send(&mut self, bytes: Bytes) -> Result<(), W::Error> {
        let writer = self.parent.writer.as_mut().unwrap();
        let mut encoded = Vec::new();
        encode_body_chunk(&bytes, &mut encoded);
        write_bytes(writer, Bytes::from(encoded)).await
    }

    pub async fn finish(mut self) -> Result<(), W::Error> {
        let writer = self.parent.writer.as_mut().unwrap();
        let mut encoded = Vec::new();
        encode_end_part(&mut encoded);
        write_bytes(writer, Bytes::from(encoded)).await?;
        self.finished = true;
        Ok(())
    }
}

impl<M, W> Drop for DownloadPartWriter<'_, M, W>
where
    M: DownloadRpc,
    W: RpcWrite,
{
    fn drop(&mut self) {
        if !self.finished {
            if let Some(writer) = self.parent.writer.take() {
                writer.close(StreamCloseCode::DROPPED);
            }
        }
    }
}

pub(crate) async fn handle_download_inner<S, M, St, H, HF, E>(
    state: S,
    config: RouterConfig,
    mut reader: St::Reader,
    writer: St::Writer,
    handle: H,
    handle_error: E,
) where
    M: DownloadRpc + 'static,
    St: RpcStream + 'static,
    H: FnOnce(S, M::Request, DownloadStart<M, St::Writer>) -> HF,
    HF: Future<Output = ()>,
    E: FnOnce(&S, &RpcError<M::Error, St::Error>),
{
    let request = match read_eof_request::<M::Request, _>(&mut reader, config).await {
        Ok(request) => request,
        Err(error) => {
            let code = error.close_code();
            handle_error(&state, &error);
            if let Some(code) = code {
                reader.close(code);
                writer.close(code);
            }
            return;
        }
    };

    handle(state, request, DownloadStart::new(writer)).await;
}
