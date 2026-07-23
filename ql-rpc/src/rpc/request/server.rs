use std::{future::Future, marker::PhantomData};

use bytes::Bytes;
use ql_common::ResetCode;

use crate::{
    finish_bytes, request::Request, rpc::read_eof_request, write_bytes, Context, DropResetWrite,
    RouterConfig, RpcCodec, RpcError, RpcRead, RpcStream, RpcWrite,
};

#[trait_variant::make(RequestHandler: Send)]
pub trait RequestHandlerLocal<M, St>
where
    M: Request,
    St: RpcStream,
{
    async fn handle(
        self,
        context: Context,
        message: M::Request,
        responder: Response<M::Response, St::Writer>,
    );

    fn handle_error(&self, error: &RpcError<M::Error, St::Error>) {
        let _ = error;
    }
}

pub struct Response<T, W>
where
    W: RpcWrite,
{
    writer: DropResetWrite<W>,
    marker: PhantomData<fn() -> T>,
}

impl<T, W> Response<T, W>
where
    T: RpcCodec,
    W: RpcWrite,
{
    pub(crate) fn new(writer: W) -> Self {
        Self {
            writer: DropResetWrite::new(writer),
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

    pub fn reset(mut self, code: ResetCode) {
        DropResetWrite::reset(&mut self.writer, code);
    }
}

pub(crate) fn handle_request<S, Req, Res, Err, St, H, HF, E>(
    state: S,
    context: Context,
    config: RouterConfig,
    stream: St,
    handle: H,
    handle_error: E,
) -> impl Future<Output = ()>
where
    Req: RpcCodec<Error = Err> + 'static,
    Res: RpcCodec<Error = Err> + 'static,
    St: RpcStream + 'static,
    H: FnOnce(S, Context, Req, Response<Res, St::Writer>) -> HF,
    HF: Future<Output = ()>,
    E: FnOnce(&S, &RpcError<Err, St::Error>),
{
    let (mut reader, writer) = stream.split();

    async move {
        let request = match read_eof_request::<Req, _>(&mut reader, config).await {
            Ok(request) => request,
            Err(error) => {
                let code = error.reset_code();
                handle_error(&state, &error);
                if let Some(code) = code {
                    reader.reset(code);
                    writer.reset(code);
                }
                return;
            }
        };

        handle(state, context, request, Response::new(writer)).await;
    }
}
