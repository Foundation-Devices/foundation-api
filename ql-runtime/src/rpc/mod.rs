mod adapter;

use ql_rpc::{
    download, duplex, notification, progress, request, subscription, upload, Route, RpcRouteKey,
};

use crate::{QlStream, QlStreamError, RuntimeHandle, StreamOptions, StreamReader, StreamWriter};

type RpcResult<T, E> = Result<T, ql_rpc::RpcError<E, QlStreamError>>;

#[derive(Clone)]
pub struct RpcHandle {
    inner: RuntimeHandle,
}

impl RpcHandle {
    pub async fn notification<M>(
        &self,
        event: &M::Payload,
        options: StreamOptions,
    ) -> RpcResult<(), M::Error>
    where
        M: notification::Notification,
    {
        let stream = self.open_rpc_stream::<M, _>(options).await?;
        notification::send::<M, _>(stream, event)
            .await
            .map_err(ql_rpc::RpcError::Transport)
    }

    pub async fn request<M>(
        &self,
        request: &M::Request,
        options: StreamOptions,
    ) -> RpcResult<M::Response, M::Error>
    where
        M: request::Request,
    {
        let stream = self.open_rpc_stream::<M, _>(options).await?;
        request::call::<M, _>(stream, request).await
    }

    pub async fn subscribe<M>(
        &self,
        request: &M::Request,
        options: StreamOptions,
    ) -> RpcResult<subscription::SubscriptionCall<M, StreamReader>, M::Error>
    where
        M: subscription::Subscription,
    {
        let stream = self.open_rpc_stream::<M, _>(options).await?;
        subscription::start::<M, _>(stream, request).await
    }

    pub async fn download<M>(
        &self,
        request: &M::Request,
        options: StreamOptions,
    ) -> RpcResult<download::DownloadCall<M, StreamReader>, M::Error>
    where
        M: download::Download,
    {
        let stream = self.open_rpc_stream::<M, _>(options).await?;
        download::start::<M, _>(stream, request).await
    }

    pub async fn progress<M>(
        &self,
        request: &M::Request,
        options: StreamOptions,
    ) -> RpcResult<progress::ProgressCall<M, StreamReader>, M::Error>
    where
        M: progress::Progress,
    {
        let stream = self.open_rpc_stream::<M, _>(options).await?;
        progress::start::<M, _>(stream, request).await
    }

    pub async fn upload<M>(
        &self,
        request: &M::Request,
        options: StreamOptions,
    ) -> RpcResult<upload::UploadCall<M, StreamWriter, StreamReader>, M::Error>
    where
        M: upload::Upload,
    {
        let stream = self.open_rpc_stream::<M, _>(options).await?;
        upload::start::<M, _>(stream, request)
            .await
            .map_err(ql_rpc::RpcError::Transport)
    }

    pub async fn duplex<M>(
        &self,
        options: StreamOptions,
    ) -> RpcResult<duplex::DuplexCall<M, StreamWriter, StreamReader>, M::Error>
    where
        M: duplex::Duplex,
    {
        let stream = self.open_rpc_stream::<M, _>(options).await?;
        Ok(duplex::start::<M, _>(stream))
    }
}

impl RpcHandle {
    pub(super) fn new(inner: RuntimeHandle) -> Self {
        Self { inner }
    }

    async fn open_rpc_stream<R, E>(&self, options: StreamOptions) -> RpcResult<QlStream, E>
    where
        R: Route,
        R::Key: RpcRouteKey,
    {
        let key = R::key();
        let mut header = Vec::with_capacity(key.encoded_len());
        key.encode(&mut header);
        self.inner
            .open_stream(header.into_boxed_slice(), options)
            .await
            .map_err(QlStreamError::from)
            .map_err(ql_rpc::RpcError::Transport)
    }
}
