use std::future::Future;

use crate::{
    request::Response, rpc::read_framed_prefix, Context, MultipartReader, RouterConfig, RpcError,
    RpcRead, RpcStream, RpcWrite, Upload,
};

#[trait_variant::make(UploadHandler: Send)]
pub trait UploadHandlerLocal<M, St>
where
    M: Upload,
    St: RpcStream,
{
    async fn handle(
        self,
        context: Context,
        request: M::Request,
        upload: MultipartReader<M::PartHeader, St::Reader>,
        responder: UploadResponder<M::Response, St::Writer>,
    );

    fn handle_error(&self, error: &RpcError<M::Error, St::Error>) {
        let _ = error;
    }
}

pub type UploadResponder<T, W> = Response<T, W>;

pub(crate) fn handle_upload<M, S, St, H, HF, E>(
    state: S,
    context: Context,
    config: RouterConfig,
    stream: St,
    handle: H,
    handle_error: E,
) -> impl Future<Output = ()>
where
    M: Upload + 'static,
    St: RpcStream + 'static,
    H: FnOnce(
        S,
        Context,
        M::Request,
        MultipartReader<M::PartHeader, St::Reader>,
        UploadResponder<M::Response, St::Writer>,
    ) -> HF,
    HF: Future<Output = ()>,
    E: FnOnce(&S, &RpcError<M::Error, St::Error>),
{
    let (mut reader, mut writer) = stream.split();

    async move {
        let (request, buffered) =
            match read_framed_prefix::<M::Request, _>(&mut reader, Some(config.max_request_bytes))
                .await
            {
                Ok(value) => value,
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

        handle(
            state,
            context,
            request,
            MultipartReader::new(reader, buffered),
            Response::new(writer),
        )
        .await;
    }
}
