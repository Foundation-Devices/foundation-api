use bytes::Bytes;
use ql_rpc::download::Download as DownloadRpc;

use super::RpcError;
use crate::{QlStreamError, StreamReader};

pub struct DownloadCall<M: DownloadRpc> {
    pub(super) inner: ql_rpc::download::DownloadCall<M, StreamReader>,
}

pub struct DownloadReader {
    pub(super) inner: ql_rpc::download::DownloadReader<StreamReader>,
}

impl<M> DownloadCall<M>
where
    M: DownloadRpc,
{
    pub async fn into_reader(
        self,
    ) -> Result<(M::ResponseHeader, DownloadReader), RpcError<M::Error>> {
        let (header, inner) = self.inner.into_reader().await?;
        Ok((header, DownloadReader { inner }))
    }
}

impl DownloadReader {
    pub async fn read(&mut self, max_len: usize) -> Result<Option<Bytes>, QlStreamError> {
        self.inner.read(max_len).await
    }

    pub async fn read_chunk(&mut self) -> Result<Option<Bytes>, QlStreamError> {
        self.inner.read_chunk().await
    }

    pub fn close(self, code: ql_wire::StreamCloseCode) {
        self.inner.into_inner().close(code);
    }
}
