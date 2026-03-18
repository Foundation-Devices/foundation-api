use std::task::{Context, Poll};

mod error;
mod request_with_progress;
mod subscription;

pub use error::*;
use ql_rpc::{
    notification::{self, Notification},
    request::{self, Request as RequestRpc},
    request_with_progress::{self as rpc_request_with_progress, RequestWithProgress},
    subscription::{self as rpc_subscription, Subscription as SubscriptionRpc},
    RpcError,
};
pub use request_with_progress::*;
pub use subscription::*;

use crate::{ByteReader, OutboundStream, QlError, RuntimeHandle};

#[derive(Clone)]
pub struct RpcHandle {
    pub(crate) inner: RuntimeHandle,
}

pub(super) enum ChunkState {
    Open(ByteReader),
    Closed,
}

impl RpcHandle {
    pub async fn event<M>(&self, event: &M::Event) -> Result<(), RpcCallError<M::Error>>
    where
        M: Notification,
    {
        let mut payload = Vec::new();
        notification::encode_event::<M>(event, &mut payload).map_err(RpcCallError::Codec)?;

        let response = self
            .start_request(payload)
            .await
            .map_err(RpcCallError::Runtime)?;
        let response = read_all(response).await.map_err(RpcCallError::Runtime)?;
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
        let response = self
            .start_request(payload)
            .await
            .map_err(RpcCallError::Runtime)?;
        let response = read_all(response).await.map_err(RpcCallError::Runtime)?;
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

        let response = self
            .start_request(payload)
            .await
            .map_err(RpcCallError::Runtime)?;
        Ok(Subscription {
            chunks: ChunkState::new(response),
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

        let response = self
            .start_request(payload)
            .await
            .map_err(RpcCallError::Runtime)?;
        Ok(ProgressCall {
            chunks: ChunkState::new(response),
            reader: Some(rpc_request_with_progress::ResponseReader::new()),
            terminal: None,
        })
    }

    async fn start_request(&self, payload: Vec<u8>) -> Result<ByteReader, QlError> {
        let OutboundStream {
            mut request,
            response,
            ..
        } = self.inner.open_stream().await?;

        request.write_all(&payload).await?;
        request.finish().await?;
        Ok(response)
    }
}

impl ChunkState {
    fn new(reader: ByteReader) -> Self {
        Self::Open(reader)
    }

    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Vec<u8>>, QlError>> {
        match self {
            Self::Open(reader) => match reader.poll_next_chunk(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(Some(bytes))) => Poll::Ready(Ok(Some(bytes))),
                Poll::Ready(Ok(None)) => {
                    *self = Self::Closed;
                    Poll::Ready(Ok(None))
                }
                Poll::Ready(Err(error)) => {
                    *self = Self::Closed;
                    Poll::Ready(Err(error))
                }
            },
            Self::Closed => Poll::Ready(Ok(None)),
        }
    }
}

async fn read_all(mut reader: ByteReader) -> Result<Vec<u8>, QlError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = reader.next_chunk().await? {
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
