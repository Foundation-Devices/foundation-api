use bytes::{BufMut, Bytes};

use crate::{
    finish_bytes, read_bytes, upload::Upload, write_bytes, CallError, ChunkQueue, RpcCodec,
    RpcRead, RpcWrite,
};

pub struct UploadCall<M, W, R>
where
    M: Upload,
    W: RpcWrite,
    R: RpcRead<Error = W::Error>,
{
    writer: Option<W>,
    reader: Option<R>,
    marker: std::marker::PhantomData<fn() -> M>,
}

impl<M, W, R> UploadCall<M, W, R>
where
    M: Upload,
    W: RpcWrite,
    R: RpcRead<Error = W::Error>,
{
    pub fn new(writer: W, reader: R) -> Self {
        Self {
            writer: Some(writer),
            reader: Some(reader),
            marker: std::marker::PhantomData,
        }
    }

    pub async fn send(&mut self, bytes: Bytes) -> Result<(), W::Error> {
        let writer = self.writer.as_mut().expect("upload writer exists");
        write_bytes(writer, bytes).await
    }

    pub async fn finish(mut self) -> Result<M::Response, CallError<M::Error, W::Error>> {
        let mut writer = self.writer.take().expect("upload writer exists");
        finish_bytes(&mut writer)
            .await
            .map_err(CallError::Transport)?;

        let mut reader = self.reader.take().expect("upload reader exists");
        let mut bytes = ChunkQueue::default();

        while let Some(chunk) = read_bytes(&mut reader, usize::MAX)
            .await
            .map_err(CallError::Transport)?
        {
            bytes.push(chunk);
        }

        let value = M::Response::decode_value(&mut bytes).map_err(CallError::Codec)?;
        if bytes.remaining() > 0 {
            return Err(crate::Error::TrailingBytes.into());
        }
        Ok(value)
    }
}

impl<M, W, R> Drop for UploadCall<M, W, R>
where
    M: Upload,
    W: RpcWrite,
    R: RpcRead<Error = W::Error>,
{
    fn drop(&mut self) {
        if let Some(reader) = self.reader.take() {
            reader.close(crate::StreamCloseCode::CANCELLED);
        }
        if let Some(writer) = self.writer.take() {
            writer.close(crate::StreamCloseCode::CANCELLED);
        }
    }
}

pub fn encode_request<M: Upload>(request: &M::Request, out: &mut (impl BufMut + AsMut<[u8]>)) {
    crate::codec::encode_value_part(request, out)
}
