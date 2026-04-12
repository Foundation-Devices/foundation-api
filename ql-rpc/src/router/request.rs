use std::future::Future;

use bytes::Bytes;

use super::{
    stream::{read_bytes, write_bytes, RpcRead, RpcStream, RpcWrite},
    RouteFuture, RouterConfig,
};
use crate::{
    request::{self, Request as RequestRpc},
    ReadValueStep, RpcCodec, StreamCloseCode, ValueReader,
};

pub trait RequestHandler<M>
where
    M: RequestRpc,
{
    type Future<'a>: Future<Output = Result<M::Response, StreamCloseCode>> + 'a
    where
        Self: 'a;

    fn handle<'a>(&'a self, request: M::Request) -> Self::Future<'a>;
}

pub(super) fn handle_request<S, M, St>(
    state: &S,
    config: RouterConfig,
    stream: St,
) -> RouteFuture<'_>
where
    M: RequestRpc,
    S: RequestHandler<M>,
    St: RpcStream + 'static,
{
    Box::pin(async move {
        let (mut reader, mut writer) = stream.split();

        let request = match read_value_and_eof::<M::Request, _>(&mut reader, config).await {
            Ok(request) => request,
            Err(code) => {
                reader.close(code);
                writer.close(code);
                return;
            }
        };

        let response = match state.handle(request).await {
            Ok(response) => response,
            Err(code) => {
                writer.close(code);
                return;
            }
        };

        let mut encoded = Vec::new();
        request::encode_response::<M>(&response, &mut encoded);

        if write_bytes(&mut writer, Bytes::from(encoded))
            .await
            .is_err()
        {
            return;
        }
        writer.finish();
    })
}

async fn read_value_and_eof<T, R>(
    reader: &mut R,
    config: RouterConfig,
) -> Result<T, StreamCloseCode>
where
    T: RpcCodec,
    R: RpcRead,
{
    let mut value_reader = ValueReader::<T>::new();
    let mut total_read = 0usize;

    let value = loop {
        match value_reader.advance() {
            Ok(ReadValueStep::Value(value)) => break value,
            Ok(ReadValueStep::NeedMore(next)) => value_reader = next,
            Err(crate::CodecError::Rpc(_error)) => return Err(StreamCloseCode::REFUSED),
            Err(crate::CodecError::Codec(_error)) => return Err(StreamCloseCode::REFUSED),
        }

        let remaining = config.max_request_bytes.saturating_sub(total_read);
        if remaining == 0 {
            return Err(StreamCloseCode::LIMIT);
        }

        match read_bytes(reader, remaining).await {
            Ok(Some(chunk)) => {
                total_read += chunk.len();
                value_reader = value_reader.push(chunk);
            }
            Ok(None) => return Err(StreamCloseCode::REFUSED),
            Err(code) => return Err(code),
        }
    };

    let remaining = config.max_request_bytes.saturating_sub(total_read);
    let probe = remaining.max(1);
    match read_bytes(reader, probe).await {
        Ok(None) => Ok(value),
        Ok(Some(_)) if remaining == 0 => Err(StreamCloseCode::LIMIT),
        Ok(Some(_)) => Err(StreamCloseCode::REFUSED),
        Err(code) => Err(code),
    }
}
