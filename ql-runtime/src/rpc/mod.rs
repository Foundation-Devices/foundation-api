mod adapter;

use bytes::Bytes;
use ql_fsm::OpenStreamParams;
use ql_rpc::{download, duplex, notification, progress, request, subscription, upload};

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
        let mut payload = Vec::new();
        notification::encode_notification::<M>(event, &mut payload);
        let mut stream = self.open_rpc_stream::<M, M::Error>().await?;
        stream.reader.reset(ql_rpc::ResetCode::CANCELLED);
        stream
            .writer
            .write(Bytes::from(payload))
            .await
            .map_err(ql_rpc::RpcError::Transport)?;
        stream
            .writer
            .finish()
            .await
            .map_err(ql_rpc::RpcError::Transport)?;
        Ok(())
    }

    pub async fn request<M>(&self, request: &M::Request) -> RpcResult<M::Response, M::Error>
    where
        M: request::Request,
    {
        let mut payload = Vec::new();
        request::encode_request::<M>(request, &mut payload);
        let response = self.start_request::<M, _>(payload).await?;
        request::read_response::<M, _>(response).await
    }

    pub async fn subscribe<M>(
        &self,
        request: &M::Request,
    ) -> RpcResult<subscription::SubscriptionCall<M, StreamReader>, M::Error>
    where
        M: subscription::Subscription,
    {
        let mut payload = Vec::new();
        subscription::encode_request::<M>(request, &mut payload);
        let response = self.start_request::<M, _>(payload).await?;
        Ok(subscription::SubscriptionCall::new(response))
    }

    pub async fn download<M>(
        &self,
        request: &M::Request,
    ) -> RpcResult<download::DownloadCall<M, StreamReader>, M::Error>
    where
        M: download::Download,
    {
        let mut payload = Vec::new();
        download::encode_request::<M>(request, &mut payload);
        let response = self.start_request::<M, _>(payload).await?;
        Ok(download::DownloadCall::new(response))
    }

    pub async fn progress<M>(
        &self,
        request: &M::Request,
    ) -> RpcResult<progress::ProgressCall<M, StreamReader>, M::Error>
    where
        M: progress::Progress,
    {
        let mut payload = Vec::new();
        progress::encode_request::<M>(request, &mut payload);
        let response = self.start_request::<M, _>(payload).await?;
        Ok(progress::ProgressCall::new(response))
    }

    pub async fn upload<M>(
        &self,
        request: &M::Request,
    ) -> RpcResult<upload::UploadCall<M, StreamWriter, StreamReader>, M::Error>
    where
        M: upload::Upload,
    {
        let mut payload = Vec::new();
        upload::encode_request::<M>(request, &mut payload);
        let mut stream = self.open_rpc_stream::<M, M::Error>().await?;
        stream
            .writer
            .write(Bytes::from(payload))
            .await
            .map_err(ql_rpc::RpcError::Transport)?;
        Ok(upload::UploadCall::new(stream.writer, stream.reader))
    }

    pub async fn duplex<M>(
        &self,
    ) -> RpcResult<duplex::DuplexCall<M, StreamWriter, StreamReader>, M::Error>
    where
        M: duplex::Duplex,
    {
        let stream = self.open_rpc_stream::<M, M::Error>().await?;
        Ok(duplex::DuplexCall {
            sender: duplex::DuplexSender::new(stream.writer),
            receiver: duplex::DuplexReceiver::new(stream.reader),
        })
    }
}

impl RpcHandle {
    pub(super) fn new(inner: RuntimeHandle) -> Self {
        Self { inner }
    }

    async fn start_request<R: ql_rpc::Route, E>(
        &self,
        payload: Vec<u8>,
    ) -> RpcResult<StreamReader, E> {
        let mut stream = self.open_rpc_stream::<R, E>().await?;
        stream
            .writer
            .write(Bytes::from(payload))
            .await
            .map_err(ql_rpc::RpcError::Transport)?;
        stream.writer.queue_finish();
        Ok(stream.reader)
    }

    async fn open_rpc_stream<R: ql_rpc::Route, E>(&self) -> RpcResult<QlStream, E> {
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
