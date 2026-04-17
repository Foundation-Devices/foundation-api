mod adapter;
mod download;
mod error;
mod progress;
mod subscription;

use bytes::Bytes;
use ql_rpc::{
    download::{self as rpc_download, Download as DownloadRpc},
    notification::{self, Notification},
    progress::{self as rpc_progress, Progress},
    request::{self, Request as RequestRpc},
    subscription::{self as rpc_subscription, Subscription as SubscriptionRpc},
};

pub use self::{adapter::*, download::*, error::*, progress::*, subscription::*};
use crate::{RuntimeHandle, StreamReader};

#[derive(Clone)]
pub struct RpcHandle {
    pub(crate) inner: RuntimeHandle,
}

impl RpcHandle {
    pub async fn event<M>(&self, event: &M::Event) -> Result<(), RpcError<M::Error>>
    where
        M: Notification,
    {
        let mut payload = Vec::new();
        notification::encode_event::<M>(event, &mut payload);
        let mut stream = self
            .inner
            .open_stream(adapter::to_wire_route_id(M::ROUTE))
            .await?;
        stream.reader.close(ql_wire::StreamCloseCode::CANCELLED);
        stream.writer.write(Bytes::from(payload)).await?;
        stream.writer.finish().await?;
        Ok(())
    }

    pub async fn request<M>(&self, request: &M::Request) -> Result<M::Response, RpcError<M::Error>>
    where
        M: RequestRpc,
    {
        let mut payload = Vec::new();
        request::encode_request::<M>(request, &mut payload);
        let response = self.start_request(M::ROUTE, payload).await?;
        Ok(request::read_response::<M, _>(response).await?)
    }

    pub async fn subscribe<M>(
        &self,
        request: &M::Request,
    ) -> Result<Subscription<M>, RpcError<M::Error>>
    where
        M: SubscriptionRpc,
    {
        let mut payload = Vec::new();
        rpc_subscription::encode_request::<M>(request, &mut payload);
        let response = self.start_request(M::ROUTE, payload).await?;
        Ok(Subscription {
            inner: rpc_subscription::SubscriptionCall::new(response),
        })
    }

    pub async fn download<M>(
        &self,
        request: &M::Request,
    ) -> Result<DownloadCall<M>, RpcError<M::Error>>
    where
        M: DownloadRpc,
    {
        let mut payload = Vec::new();
        rpc_download::encode_request::<M>(request, &mut payload);
        let response = self.start_request(M::ROUTE, payload).await?;
        Ok(DownloadCall {
            inner: rpc_download::DownloadCall::new(response),
        })
    }

    pub async fn progress<M>(
        &self,
        request: &M::Request,
    ) -> Result<ProgressCall<M>, RpcError<M::Error>>
    where
        M: Progress,
    {
        let mut payload = Vec::new();
        rpc_progress::encode_request::<M>(request, &mut payload);
        let response = self.start_request(M::ROUTE, payload).await?;
        Ok(ProgressCall {
            inner: rpc_progress::ProgressCall::new(response),
        })
    }

    async fn start_request<E>(
        &self,
        route_id: ql_rpc::RouteId,
        payload: Vec<u8>,
    ) -> Result<StreamReader, RpcError<E>> {
        let mut stream = self
            .inner
            .open_stream(adapter::to_wire_route_id(route_id))
            .await?;
        stream.writer.write(Bytes::from(payload)).await?;
        stream.writer.finish().await?;
        Ok(stream.reader)
    }
}
