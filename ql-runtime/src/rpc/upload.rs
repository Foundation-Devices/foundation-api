use bytes::Bytes;
use ql_rpc::upload::Upload as UploadRpc;

use super::RpcError;
use crate::QlStreamError;

pub struct UploadCall<M: UploadRpc> {
    pub(super) inner: ql_rpc::upload::UploadCall<M, crate::StreamWriter, crate::StreamReader>,
}

pub struct UploadPartWriter<'a, M: UploadRpc> {
    inner: ql_rpc::upload::UploadPartWriter<'a, M, crate::StreamWriter, crate::StreamReader>,
}

impl<M> UploadCall<M>
where
    M: UploadRpc,
{
    pub async fn start_part(
        &mut self,
        part_header: M::PartHeader,
    ) -> Result<UploadPartWriter<'_, M>, QlStreamError> {
        Ok(UploadPartWriter {
            inner: self.inner.start_part(part_header).await?,
        })
    }

    pub async fn finish(self) -> Result<M::Response, RpcError<M::Error>> {
        self.inner.finish().await.map_err(RpcError::from)
    }
}

impl<M> UploadPartWriter<'_, M>
where
    M: UploadRpc,
{
    pub async fn send(&mut self, bytes: Bytes) -> Result<(), QlStreamError> {
        self.inner.send(bytes).await
    }

    pub async fn finish(self) -> Result<(), QlStreamError> {
        self.inner.finish().await
    }
}
