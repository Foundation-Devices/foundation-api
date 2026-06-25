use bytes::Bytes;
use ql_common::ResetCode;

use crate::{
    rpc::{
        parts::{encode_body_chunk, encode_end_part, encode_finish, encode_part_header},
        read_eof_value,
    },
    upload::Upload,
    write_bytes, DropResetRead, DropResetWrite, RpcError, RpcRead, RpcStream, RpcWrite,
};

pub async fn start<M, St>(
    stream: St,
    request: &M::Request,
) -> Result<UploadCall<M, St::Writer, St::Reader>, St::Error>
where
    M: Upload,
    St: RpcStream,
{
    let (reader, mut writer) = stream.split();
    let mut payload = Vec::new();
    crate::codec::encode_value_part(request, &mut payload);
    write_bytes(&mut writer, Bytes::from(payload)).await?;
    Ok(UploadCall::new(writer, reader))
}

pub struct UploadCall<M, W, R>
where
    M: Upload,
    W: RpcWrite,
    R: RpcRead<Error = W::Error>,
{
    writer: DropResetWrite<W>,
    reader: DropResetRead<R>,
    marker: std::marker::PhantomData<fn() -> M>,
}

pub struct UploadPartWriter<'a, M, W, R>
where
    M: Upload,
    W: RpcWrite,
    R: RpcRead<Error = W::Error>,
{
    parent: &'a mut UploadCall<M, W, R>,
    finished: bool,
}

impl<M, W, R> UploadCall<M, W, R>
where
    M: Upload,
    W: RpcWrite,
    R: RpcRead<Error = W::Error>,
{
    pub fn new(writer: W, reader: R) -> Self {
        Self {
            writer: DropResetWrite::new(writer),
            reader: DropResetRead::new(reader),
            marker: std::marker::PhantomData,
        }
    }

    pub async fn start_part(
        &mut self,
        part_header: M::PartHeader,
    ) -> Result<UploadPartWriter<'_, M, W, R>, W::Error> {
        let writer = &mut self.writer;
        let mut encoded = Vec::new();
        encode_part_header(&part_header, &mut encoded);
        write_bytes(writer, Bytes::from(encoded)).await?;
        Ok(UploadPartWriter {
            parent: self,
            finished: false,
        })
    }

    pub async fn finish(mut self) -> Result<M::Response, RpcError<M::Error, W::Error>> {
        let writer = &mut self.writer;
        let mut encoded = Vec::new();
        encode_finish(&mut encoded);
        write_bytes(writer, Bytes::from(encoded))
            .await
            .map_err(RpcError::Transport)?;
        writer.queue_finish();

        read_eof_value::<M::Response, _>(&mut self.reader).await
    }

    fn reset(&mut self, code: ResetCode) {
        DropResetRead::reset(&mut self.reader, code);
        DropResetWrite::reset(&mut self.writer, code);
    }
}

impl<M, W, R> UploadPartWriter<'_, M, W, R>
where
    M: Upload,
    W: RpcWrite,
    R: RpcRead<Error = W::Error>,
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

impl<M, W, R> Drop for UploadPartWriter<'_, M, W, R>
where
    M: Upload,
    W: RpcWrite,
    R: RpcRead<Error = W::Error>,
{
    fn drop(&mut self) {
        if !self.finished {
            self.parent.reset(ResetCode::DROPPED);
        }
    }
}
