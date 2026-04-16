use std::marker::PhantomData;

use bytes::Bytes;

use crate::{
    finish_bytes, read_bytes, request::Request as RequestRpc, write_bytes, ChunkQueue,
    RpcCodec, RpcRead, RpcStream, RpcWrite, StreamCloseCode, StreamError,
};

use crate::RouterConfig;

pub trait RequestHandler<M, St>
where
    M: RequestRpc,
    St: RpcStream,
{
    fn handle(self, message: M::Request, responder: Response<M::Response, St::Writer>);

    fn handle_transport_error(&self, _error: &St::Error) {}
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
    pub(crate) fn new(writer: W) -> Self {
        Self {
            writer: Some(writer),
            marker: PhantomData,
        }
    }

    pub async fn respond(mut self, response: T) -> Result<(), W::Error> {
        let mut writer = self.writer.take().expect("response writer exists");
        let mut encoded = Vec::new();
        response.encode_value(&mut encoded);
        write_bytes(&mut writer, Bytes::from(encoded)).await?;
        finish_bytes(&mut writer).await?;
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

pub(crate) async fn handle_request_inner<S, M, St>(
    state: S,
    config: RouterConfig,
    mut reader: St::Reader,
    writer: St::Writer,
) where
    M: RequestRpc + 'static,
    S: RequestHandler<M, St> + 'static,
    St: RpcStream + 'static,
{
    let request = match read_whole_value::<M::Request, _>(&mut reader, config).await {
        Ok(request) => request,
        Err(error) => {
            let code = error.close_code();
            state.handle_transport_error(&error);
            if let Some(code) = code {
                reader.close(code);
                writer.close(code);
            }
            return;
        }
    };

    state.handle(request, Response::new(writer));
}

pub(crate) async fn read_whole_value<T, R>(
    reader: &mut R,
    config: RouterConfig,
) -> Result<T, R::Error>
where
    T: RpcCodec,
    R: RpcRead,
{
    let mut bytes = ChunkQueue::default();
    let mut total_read = 0usize;

    loop {
        let remaining = config.max_request_bytes.saturating_sub(total_read);
        let probe = remaining.max(1);
        match read_bytes(reader, probe).await {
            Ok(Some(chunk)) => {
                if chunk.len() > remaining {
                    return Err(StreamCloseCode::LIMIT.into());
                }
                total_read += chunk.len();
                bytes.push(chunk);
            }
            Ok(None) => break,
            Err(error) => return Err(error),
        }
    }

    let value = T::decode_value(&mut bytes).map_err(|_error| StreamCloseCode::REFUSED)?;
    if bytes.remaining() > 0 {
        return Err(StreamCloseCode::REFUSED.into());
    }
    Ok(value)
}
