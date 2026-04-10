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
    ReadValueStep, RpcCodec, RpcError, ValueReader,
};
use ql_wire::{RouteId, VarInt};

pub use self::{error::*, request_with_progress::*, subscription::*};
use crate::{ByteReader, RuntimeHandle};

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
        let route_id = RouteId(VarInt::from_u32(M::METHOD.0));
        let mut stream = self.inner.open_stream(route_id).await?;
        stream.reader.close(ql_wire::StreamCloseCode(0));
        stream.writer.write(Bytes::from(payload)).await?;
        Ok(())
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
        let response = self.start_request(M::METHOD, payload).await?;
        read_value::<M::Response>(response).await
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
        let response = self.start_request(M::METHOD, payload).await?;
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
        let response = self.start_request(M::METHOD, payload).await?;
        Ok(ProgressCall {
            stream: response,
            reader: Some(rpc_request_with_progress::ResponseReader::new()),
            terminal: None,
        })
    }

    async fn start_request<E>(
        &self,
        method: ql_rpc::MethodId,
        payload: Vec<u8>,
    ) -> Result<ByteReader, RpcCallError<E>> {
        let route_id = RouteId(VarInt::from_u32(method.0));
        let mut stream = self.inner.open_stream(route_id).await?;
        stream.writer.write(Bytes::from(payload)).await?;
        stream.writer.finish();
        Ok(stream.reader)
    }
}

async fn read_value<T>(mut reader: ByteReader) -> Result<T, RpcCallError<T::Error>>
where
    T: RpcCodec,
{
    let mut value_reader = ValueReader::<T>::new();

    loop {
        match value_reader.advance().map_err(RpcCallError::from)? {
            ReadValueStep::Value(value) => return Ok(value),
            ReadValueStep::NeedMore(next) => value_reader = next,
        }

        match poll_fn(|cx| reader.poll_read_chunk(cx)).await? {
            Some(chunk) => value_reader = value_reader.push(chunk),
            None => return Err(RpcError::Truncated.into()),
        }
    }
}
