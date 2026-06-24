mod adapter;

use ql_fsm::OpenStreamParams;
use ql_rpc::{download, duplex, notification, progress, request, subscription, upload, Route};

use crate::{QlStream, QlStreamError, RuntimeHandle, StreamReader, StreamWriter};

type RpcResult<T, E> = Result<T, ql_rpc::RpcError<E, QlStreamError>>;

#[derive(Clone)]
pub struct RpcHandle {
    inner: RuntimeHandle,
}

impl RpcHandle {
    pub async fn notification<M>(&self, event: &M::Payload) -> RpcResult<(), M::Error>
    where
        M: notification::Notification,
    {
        let stream = self.open_rpc_stream::<M, _>().await?;
        notification::send::<M, _, _>(stream.reader, stream.writer, event)
            .await
            .map_err(ql_rpc::RpcError::Transport)
    }

    pub async fn request<M>(&self, request: &M::Request) -> RpcResult<M::Response, M::Error>
    where
        M: request::Request,
    {
        let stream = self.open_rpc_stream::<M, _>().await?;
        request::call::<M, _, _>(stream.reader, stream.writer, request).await
    }

    pub async fn subscribe<M>(
        &self,
        request: &M::Request,
    ) -> RpcResult<subscription::SubscriptionCall<M, StreamReader>, M::Error>
    where
        M: subscription::Subscription,
    {
        let stream = self.open_rpc_stream::<M, _>().await?;
        subscription::start::<M, _, _>(stream.reader, stream.writer, request).await
    }

    pub async fn download<M>(
        &self,
        request: &M::Request,
    ) -> RpcResult<download::DownloadCall<M, StreamReader>, M::Error>
    where
        M: download::Download,
    {
        let stream = self.open_rpc_stream::<M, _>().await?;
        download::start::<M, _, _>(stream.reader, stream.writer, request).await
    }

    pub async fn progress<M>(
        &self,
        request: &M::Request,
    ) -> RpcResult<progress::ProgressCall<M, StreamReader>, M::Error>
    where
        M: progress::Progress,
    {
        let stream = self.open_rpc_stream::<M, _>().await?;
        progress::start::<M, _, _>(stream.reader, stream.writer, request).await
    }

    pub async fn upload<M>(
        &self,
        request: &M::Request,
    ) -> RpcResult<upload::UploadCall<M, StreamWriter, StreamReader>, M::Error>
    where
        M: upload::Upload,
    {
        let stream = self.open_rpc_stream::<M, _>().await?;
        upload::start::<M, _, _>(stream.writer, stream.reader, request)
            .await
            .map_err(ql_rpc::RpcError::Transport)
    }

    pub async fn duplex<M>(
        &self,
    ) -> RpcResult<duplex::DuplexCall<M, StreamWriter, StreamReader>, M::Error>
    where
        M: duplex::Duplex,
    {
        let stream = self.open_rpc_stream::<M, _>().await?;
        Ok(duplex::start::<M, _, _>(stream.writer, stream.reader))
    }
}

impl RpcHandle {
    pub(super) fn new(inner: RuntimeHandle) -> Self {
        Self { inner }
    }

    async fn open_rpc_stream<R: Route, E>(&self) -> RpcResult<QlStream, E> {
        self.inner
            .open_stream(OpenStreamParams {
                service_id: R::SERVICE,
                route_id: R::ROUTE,
            })
            .await
            .map_err(QlStreamError::from)
            .map_err(ql_rpc::RpcError::Transport)
    }
}
