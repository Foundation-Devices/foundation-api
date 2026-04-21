use std::marker::PhantomData;

use bytes::Bytes;

use crate::{
    finish_bytes, request::Request as RequestRpc, rpc::read_eof_request, write_bytes, RouterConfig,
    RpcCodec, RpcRead, RpcStream, RpcWrite, StreamCloseCode, StreamError,
};

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
    let request = match read_eof_request::<M::Request, _>(&mut reader, config).await {
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
