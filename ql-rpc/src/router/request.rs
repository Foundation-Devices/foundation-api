use std::marker::PhantomData;

use bytes::Bytes;

use super::{
    stream::{read_bytes, write_bytes, RpcRead, RpcStream, RpcWrite},
    LocalMode, RouteMode, RouterConfig, SendMode,
};
use crate::{
    codec, request::Request as RequestRpc, ReadValueStep, RpcCodec, StreamCloseCode, ValueReader,
};

pub trait RequestHandler<M, St>
where
    M: RequestRpc,
    St: RpcStream,
{
    fn handle(self, message: M::Request, responder: Response<M::Response, St::Writer>);
}

pub struct Response<T, W>
where
    W: RpcWrite,
{
    writer: Option<W>,
    marker: PhantomData<fn() -> T>,
}

impl<T, W> Response<T, W>
where
    T: RpcCodec,
    W: RpcWrite,
{
    fn new(writer: W) -> Self {
        Self {
            writer: Some(writer),
            marker: PhantomData,
        }
    }

    pub async fn respond(mut self, response: T) -> Result<(), StreamCloseCode> {
        let mut writer = self.writer.take().expect("response writer exists");
        let mut encoded = Vec::new();
        codec::encode_value_part(&response, &mut encoded);
        if let Err(code) = write_bytes(&mut writer, Bytes::from(encoded)).await {
            writer.close(code);
            return Err(code);
        }
        writer.finish();
        Ok(())
    }

    pub fn close(mut self, code: StreamCloseCode) {
        if let Some(writer) = self.writer.take() {
            writer.close(code);
        }
    }
}

impl<T, W> Drop for Response<T, W>
where
    W: RpcWrite,
{
    fn drop(&mut self) {
        if let Some(writer) = self.writer.take() {
            writer.close(StreamCloseCode::CANCELLED);
        }
    }
}

#[doc(hidden)]
pub trait RequestRouteMode<S, M, St>: RouteMode
where
    M: RequestRpc + 'static,
    S: RequestHandler<M, St> + 'static,
    St: RpcStream + 'static,
{
    fn handle_request(state: S, config: RouterConfig, stream: St) -> Self::RouteFuture;
}

impl<S, M, St> RequestRouteMode<S, M, St> for LocalMode
where
    M: RequestRpc + 'static,
    S: RequestHandler<M, St> + 'static,
    St: RpcStream + 'static,
{
    fn handle_request(state: S, config: RouterConfig, stream: St) -> Self::RouteFuture {
        let (reader, writer) = stream.split();
        Box::pin(handle_request_inner::<S, M, St>(
            state, config, reader, writer,
        ))
    }
}

impl<S, M, St> RequestRouteMode<S, M, St> for SendMode
where
    M: RequestRpc + 'static,
    M::Request: Send + 'static,
    S: RequestHandler<M, St> + Send + 'static,
    St: RpcStream + 'static,
    St::Reader: Send + 'static,
    St::Writer: Send + 'static,
{
    fn handle_request(state: S, config: RouterConfig, stream: St) -> Self::RouteFuture {
        let (reader, writer) = stream.split();
        Box::pin(handle_request_inner::<S, M, St>(
            state, config, reader, writer,
        ))
    }
}

async fn handle_request_inner<S, M, St>(
    state: S,
    config: RouterConfig,
    mut reader: St::Reader,
    writer: St::Writer,
) where
    M: RequestRpc + 'static,
    S: RequestHandler<M, St> + 'static,
    St: RpcStream + 'static,
{
    let request = match read_value_and_eof::<M::Request, _>(&mut reader, config).await {
        Ok(request) => request,
        Err(code) => {
            reader.close(code);
            writer.close(code);
            return;
        }
    };

    state.handle(request, Response::new(writer));
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
