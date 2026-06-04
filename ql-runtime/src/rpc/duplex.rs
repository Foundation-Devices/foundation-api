use futures_lite::future::poll_fn;
use ql_rpc::duplex::Duplex as DuplexRpc;

use super::RpcError;
use crate::{QlStreamError, StreamReader, StreamWriter};

pub struct DuplexCall<M: DuplexRpc> {
    pub sender: DuplexSender<M::InitiatorEvent>,
    pub receiver: DuplexReceiver<M::ResponderEvent>,
}

pub struct DuplexSender<T>
where
    T: ql_rpc::RpcCodec,
{
    pub(super) inner: ql_rpc::duplex::DuplexSender<T, StreamWriter>,
}

pub struct DuplexReceiver<T>
where
    T: ql_rpc::RpcCodec,
{
    pub(super) inner: ql_rpc::duplex::DuplexReceiver<T, StreamReader>,
}

impl<T> DuplexSender<T>
where
    T: ql_rpc::RpcCodec,
{
    pub async fn send(&mut self, event: &T) -> Result<(), QlStreamError> {
        self.inner.send(event).await
    }

    pub async fn finish(self) -> Result<(), QlStreamError> {
        self.inner.finish().await
    }

    pub fn close(self, code: ql_wire::StreamCloseCode) {
        self.inner.close(ql_rpc::StreamCloseCode(code.0));
    }
}

impl<T> DuplexReceiver<T>
where
    T: ql_rpc::RpcCodec,
{
    pub async fn next_event(&mut self) -> Option<Result<T, RpcError<T::Error>>> {
        poll_fn(|cx| {
            self.inner
                .poll_next_event(cx)
                .map(|item| item.map(|result| Ok(result?)))
        })
        .await
    }

    pub fn close(self, code: ql_wire::StreamCloseCode) {
        self.inner.close(ql_rpc::StreamCloseCode(code.0));
    }
}
