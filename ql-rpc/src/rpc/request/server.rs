use std::{future::Future, marker::PhantomData};

use bytes::Bytes;

use crate::{
    finish_bytes, request::Request as RequestRpc, rpc::read_eof_request, write_bytes,
    DropCloseWrite, RouterConfig, RpcCodec, RpcError, RpcRead, RpcStream, RpcWrite,
    StreamCloseCode,
};

#[trait_variant::make(RequestHandler: Send)]
pub trait RequestHandlerLocal<M, St>
where
    M: RequestRpc,
    St: RpcStream,
{
    async fn handle(self, message: M::Request, responder: Response<M::Response, St::Writer>);

    fn handle_error(&self, _error: &RpcError<M::Error, St::Error>) {}
}

pub struct Response<T, W>
where
    W: RpcWrite,
{
    writer: DropCloseWrite<W>,
    marker: PhantomData<fn() -> T>,
}

impl<T, W> Response<T, W>
where
    T: RpcCodec,
    W: RpcWrite,
{
    pub(crate) fn new(writer: W) -> Self {
        Self {
            writer: DropCloseWrite::new(writer),
            marker: PhantomData,
        }
    }

    pub async fn respond(mut self, response: T) -> Result<(), W::Error> {
        let writer = &mut self.writer;
        let mut encoded = Vec::new();
        response.encode_value(&mut encoded);
        write_bytes(writer, Bytes::from(encoded)).await?;
        finish_bytes(writer).await?;
        Ok(())
    }

    pub fn close(mut self, code: StreamCloseCode) {
        DropCloseWrite::close(&mut self.writer, code);
    }
}

pub(crate) async fn handle_request_inner<S, M, St, H, HF, E>(
    state: S,
    config: RouterConfig,
    mut reader: St::Reader,
    writer: St::Writer,
    handle: H,
    handle_error: E,
) where
    M: RequestRpc + 'static,
    St: RpcStream + 'static,
    H: FnOnce(S, M::Request, Response<M::Response, St::Writer>) -> HF,
    HF: Future<Output = ()>,
    E: FnOnce(&S, &RpcError<M::Error, St::Error>),
{
    let request = match read_eof_request::<M::Request, _>(&mut reader, config).await {
        Ok(request) => request,
        Err(error) => {
            let code = error.close_code();
            handle_error(&state, &error);
            if let Some(code) = code {
                reader.close(code);
                writer.close(code);
            }
            return;
        }
    };

    handle(state, request, Response::new(writer)).await;
}
