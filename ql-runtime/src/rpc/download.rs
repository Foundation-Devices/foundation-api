use bytes::Bytes;
use ql_rpc::download::Download as DownloadRpc;

use super::RpcError;
use crate::StreamReader;

pub struct DownloadCall<M: DownloadRpc> {
    pub(super) inner: ql_rpc::download::DownloadCall<M, StreamReader>,
}

pub struct DownloadReader<M: DownloadRpc> {
    pub(super) inner: ql_rpc::download::DownloadReader<M, StreamReader>,
}

pub struct DownloadPart<'a, M: DownloadRpc> {
    inner: ql_rpc::download::DownloadPart<'a, M, StreamReader>,
}

impl<M> DownloadCall<M>
where
    M: DownloadRpc,
{
    pub async fn start(self) -> Result<(M::ResponseHeader, DownloadReader<M>), RpcError<M::Error>> {
        let (header, inner) = self.inner.start().await?;
        Ok((header, DownloadReader { inner }))
    }

    pub fn close(self, code: ql_wire::StreamCloseCode) {
        self.inner.close(ql_rpc::StreamCloseCode(code.0));
    }
}

impl<M> DownloadReader<M>
where
    M: DownloadRpc,
{
    pub async fn next_part(
        &mut self,
    ) -> Result<Option<(M::PartHeader, DownloadPart<'_, M>)>, RpcError<M::Error>> {
        Ok(self
            .inner
            .next_part()
            .await?
            .map(|(header, inner)| (header, DownloadPart { inner })))
    }

    pub async fn complete(self) -> Result<(), RpcError<M::Error>> {
        self.inner.complete().await.map_err(RpcError::from)
    }

    pub fn close(self, code: ql_wire::StreamCloseCode) {
        self.inner.close(ql_rpc::StreamCloseCode(code.0));
    }
}

impl<M> DownloadPart<'_, M>
where
    M: DownloadRpc,
{
    pub async fn read_chunk(&mut self) -> Result<Option<Bytes>, RpcError<M::Error>> {
        Ok(self.inner.read_chunk().await?)
    }

    pub fn close(self, code: ql_wire::StreamCloseCode) {
        self.inner.close(ql_rpc::StreamCloseCode(code.0));
    }
}
