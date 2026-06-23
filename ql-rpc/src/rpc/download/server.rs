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
    write_bytes, DropResetWrite, ResetCode, RouterConfig, RpcError, RpcRead, RpcStream, RpcWrite,
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
    writer: DropResetWrite<W>,
    marker: PhantomData<fn() -> M>,
}

pub struct DownloadWriter<M, W>
where
    M: DownloadRpc,
    W: RpcWrite,
{
    writer: DropResetWrite<W>,
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
            writer: DropResetWrite::new(writer),
            marker: PhantomData,
        }
    }

    /// send the response header and begin streaming parts
    pub async fn start(
        self,
        response_header: M::ResponseHeader,
    ) -> Result<DownloadWriter<M, W>, W::Error> {
        let mut writer = self.writer;
        let mut encoded = Vec::new();
        codec::encode_value_part(&response_header, &mut encoded);
        write_bytes(&mut writer, Bytes::from(encoded)).await?;
        Ok(DownloadWriter {
            writer,
            marker: PhantomData,
        })
    }

    /// send a header-only response and finish the stream
    pub async fn complete(self, response_header: M::ResponseHeader) -> Result<(), W::Error> {
        let mut writer = self.writer;
        let mut encoded = Vec::new();
        codec::encode_value_part(&response_header, &mut encoded);
        encode_finish(&mut encoded);
        write_bytes(&mut writer, Bytes::from(encoded)).await?;
        finish_bytes(&mut writer).await
    }

    /// reset the stream with a transport code
    pub fn reset(mut self, code: ResetCode) {
        DropResetWrite::reset(&mut self.writer, code);
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
        let writer = &mut self.writer;
        let mut encoded = Vec::new();
        encode_part_header(&part_header, &mut encoded);
        write_bytes(writer, Bytes::from(encoded)).await?;
        Ok(DownloadPartWriter {
            parent: self,
            finished: false,
        })
    }

    pub async fn finish(self) -> Result<(), W::Error> {
        let mut writer = self.writer;
        let mut encoded = Vec::new();
        encode_finish(&mut encoded);
        write_bytes(&mut writer, Bytes::from(encoded)).await?;
        finish_bytes(&mut writer).await
    }

    pub fn reset(mut self, code: ResetCode) {
        DropResetWrite::reset(&mut self.writer, code);
    }
}

impl<M, W> DownloadPartWriter<'_, M, W>
where
    M: DownloadRpc,
    W: RpcWrite,
{
    pub async fn send(&mut self, bytes: Bytes) -> Result<(), W::Error> {
        let writer = &mut self.parent.writer;
        let mut encoded = Vec::new();
        encode_body_chunk(&bytes, &mut encoded);
        write_bytes(writer, Bytes::from(encoded)).await
    }

    pub async fn finish(mut self) -> Result<(), W::Error> {
        let writer = &mut self.parent.writer;
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
            DropResetWrite::reset(&mut self.parent.writer, ResetCode::DROPPED);
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
            let code = error.reset_code();
            handle_error(&state, &error);
            if let Some(code) = code {
                reader.reset(code);
                writer.reset(code);
            }
            return;
        }
    };

    handle(state, request, DownloadStart::new(writer)).await;
}
