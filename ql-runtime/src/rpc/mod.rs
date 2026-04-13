mod adapter;
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
    Error, ReadValueStep, RpcCodec, ValueReader,
};

pub use self::{adapter::*, error::*, request_with_progress::*, subscription::*};
use crate::{ByteReader, RuntimeHandle};

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
        stream.writer.finish();
        Ok(())
    }

    pub async fn request<M>(&self, request: &M::Request) -> Result<M::Response, RpcError<M::Error>>
    where
        M: RequestRpc,
    {
        let mut payload = Vec::new();
        request::encode_request::<M>(request, &mut payload);
        let response = self.start_request(M::ROUTE, payload).await?;
        read_value::<M::Response>(response).await
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
            stream: response,
            reader: Some(rpc_subscription::ResponseReader::new()),
        })
    }

    pub async fn request_with_progress<M>(
        &self,
        request: &M::Request,
    ) -> Result<ProgressCall<M>, RpcError<M::Error>>
    where
        M: RequestWithProgress,
    {
        let mut payload = Vec::new();
        rpc_request_with_progress::encode_request::<M>(request, &mut payload);
        let response = self.start_request(M::ROUTE, payload).await?;
        Ok(ProgressCall {
            stream: response,
            reader: Some(rpc_request_with_progress::ResponseReader::new()),
            terminal: None,
        })
    }

    async fn start_request<E>(
        &self,
        route_id: ql_rpc::RouteId,
        payload: Vec<u8>,
    ) -> Result<ByteReader, RpcError<E>> {
        let mut stream = self
            .inner
            .open_stream(adapter::to_wire_route_id(route_id))
            .await?;
        stream.writer.write(Bytes::from(payload)).await?;
        stream.writer.finish();
        Ok(stream.reader)
    }
}

async fn read_value<T>(mut reader: ByteReader) -> Result<T, RpcError<T::Error>>
where
    T: RpcCodec,
{
    let mut value_reader = ValueReader::<T>::new();

    loop {
        match value_reader.advance().map_err(RpcError::from)? {
            ReadValueStep::Value(value) => return Ok(value),
            ReadValueStep::NeedMore(next) => value_reader = next,
        }

        match poll_fn(|cx| reader.poll_read_chunk(cx)).await? {
            Some(chunk) => value_reader = value_reader.push(chunk),
            None => return Err(Error::Truncated.into()),
        }
    }
}
