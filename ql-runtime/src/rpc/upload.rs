use bytes::Bytes;
use ql_rpc::upload::Upload as UploadRpc;

use super::RpcError;
use crate::QlStreamError;

pub struct UploadCall<M: UploadRpc> {
    pub(super) inner: ql_rpc::upload::UploadCall<M, crate::StreamWriter, crate::StreamReader>,
}

impl<M> UploadCall<M>
where
    M: UploadRpc,
{
    pub async fn send(&mut self, bytes: Bytes) -> Result<(), QlStreamError> {
        self.inner.send(bytes).await
    }

    pub async fn finish(self) -> Result<M::Response, RpcError<M::Error>> {
        self.inner.finish().await.map_err(RpcError::from)
    }
}
