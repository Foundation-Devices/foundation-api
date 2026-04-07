mod error;
mod request_with_progress;
mod subscription;

use std::future::poll_fn;

use bytes::Bytes;
use ql_rpc::{
    notification::{self, Notification},
    request::{self, Request as RequestRpc},
    request_with_progress::{self as rpc_request_with_progress, RequestWithProgress},
    subscription::{self as rpc_subscription, Subscription as SubscriptionRpc},
    RpcError,
};

pub use self::{error::*, request_with_progress::*, subscription::*};
use crate::{ByteReader, QlError, RuntimeHandle};

#[derive(Clone)]
pub struct RpcHandle {
    pub(crate) inner: RuntimeHandle,
}

impl RpcHandle {
    pub async fn event<M>(&self, event: &M::Event) -> Result<(), RpcCallError<M::Error>>
    where
        M: Notification,
    {
        let mut payload = Vec::new();
        notification::encode_event::<M>(event, &mut payload).map_err(RpcCallError::Codec)?;
        let response = self.start_request(payload).await?;
        let response = read_all(response).await?;
        if response.is_empty() {
            Ok(())
        } else {
            Err(RpcCallError::Rpc(RpcError::TrailingBytes))
        }
    }

    pub async fn request<M>(
        &self,
        request: &M::Request,
    ) -> Result<M::Response, RpcCallError<M::Error>>
    where
        M: RequestRpc,
    {
        let mut payload = Vec::new();
        request::encode_request::<M>(request, &mut payload).map_err(RpcCallError::Codec)?;
        let response = self.start_request(payload).await?;
        let response = read_all(response).await?;
        request::decode_response::<M>(&response).map_err(RpcCallError::Codec)
    }

    pub async fn subscribe<M>(
        &self,
        request: &M::Request,
    ) -> Result<Subscription<M>, RpcCallError<M::Error>>
    where
        M: SubscriptionRpc,
    {
        let mut payload = Vec::new();
        rpc_subscription::encode_request::<M>(request, &mut payload)
            .map_err(RpcCallError::Codec)?;
        let response = self.start_request(payload).await?;
        Ok(Subscription {
            stream: response,
            reader: Some(rpc_subscription::ResponseReader::new()),
        })
    }

    pub async fn request_with_progress<M>(
        &self,
        request: &M::Request,
    ) -> Result<ProgressCall<M>, RpcCallError<M::Error>>
    where
        M: RequestWithProgress,
    {
        let mut payload = Vec::new();
        rpc_request_with_progress::encode_request::<M>(request, &mut payload)
            .map_err(RpcCallError::Codec)?;
        let response = self.start_request(payload).await?;
        Ok(ProgressCall {
            stream: response,
            reader: Some(rpc_request_with_progress::ResponseReader::new()),
            terminal: None,
        })
    }

    async fn start_request(&self, payload: Vec<u8>) -> Result<ByteReader, QlError> {
        let mut stream = self.inner.open_stream().await?;
        stream.writer.write(Bytes::from(payload)).await?;
        stream.writer.finish();
        Ok(stream.reader)
    }
}

async fn read_all(mut reader: ByteReader) -> Result<Vec<u8>, QlError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = poll_fn(|cx| reader.poll_read_chunk(cx))
        .await
        .map_err(QlError::from)?
    {
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
