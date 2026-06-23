use bytes::{BufMut, Bytes};

use crate::{
    finish_bytes, read_bytes,
    rpc::parts::{encode_body_chunk, encode_end_part, encode_finish, encode_part_header},
    upload::Upload,
    write_bytes, ChunkQueue, DropCloseRead, DropCloseWrite, RpcCodec, RpcError, RpcRead, RpcWrite,
    StreamCloseCode,
};

pub struct UploadCall<M, W, R>
where
    M: Upload,
    W: RpcWrite,
    R: RpcRead<Error = W::Error>,
{
    writer: DropCloseWrite<W>,
    reader: DropCloseRead<R>,
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
            writer: DropCloseWrite::new(writer),
            reader: DropCloseRead::new(reader),
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
        finish_bytes(writer).await.map_err(RpcError::Transport)?;

        let reader = &mut self.reader;
        let mut bytes = ChunkQueue::default();

        while let Some(chunk) = read_bytes(reader).await.map_err(RpcError::Transport)? {
            bytes.push(chunk);
        }

        let value = M::Response::decode_value(&mut bytes).map_err(RpcError::Codec)?;
        if bytes.remaining() > 0 {
            return Err(crate::Error::TrailingBytes.into());
        }
        Ok(value)
    }

    fn close(&mut self, code: StreamCloseCode) {
        DropCloseRead::close(&mut self.reader, code);
        DropCloseWrite::close(&mut self.writer, code);
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
            self.parent.close(StreamCloseCode::DROPPED);
        }
    }
}

pub fn encode_request<M: Upload>(request: &M::Request, out: &mut (impl BufMut + AsMut<[u8]>)) {
    crate::codec::encode_value_part(request, out)
}
