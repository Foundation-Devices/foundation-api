use std::{future::Future, marker::PhantomData};

use bytes::Bytes;

use crate::{
    codec, finish_bytes,
    progress::Progress,
    rpc::{progress::codec::FrameKind, read_framed_request},
    write_bytes, Context, DropResetWrite, ResetCode, RouterConfig, RpcError, RpcRead, RpcStream,
    RpcWrite,
};

#[trait_variant::make(ProgressHandler: Send)]
pub trait ProgressHandlerLocal<M, St>
where
    M: Progress,
    St: RpcStream,
{
    async fn handle(
        self,
        context: Context,
        request: M::Request,
        responder: ProgressResponder<M, St::Writer>,
    );

    fn handle_error(&self, _error: &RpcError<M::Error, St::Error>) {}
}

pub struct ProgressResponder<M, W>
where
    M: Progress,
    W: RpcWrite,
{
    writer: DropResetWrite<W>,
    marker: PhantomData<fn() -> M>,
}

impl<M, W> ProgressResponder<M, W>
where
    M: Progress,
    W: RpcWrite,
{
    pub async fn send(&mut self, progress: M::Progress) -> Result<(), W::Error> {
        let writer = &mut self.writer;
        let mut encoded = Vec::new();
        codec::encode_tagged_value_part(FrameKind::Progress as u8, &progress, &mut encoded);
        write_bytes(writer, Bytes::from(encoded)).await
    }

    pub async fn finish(mut self, response: M::Response) -> Result<(), W::Error> {
        let mut encoded = Vec::new();
        codec::encode_tagged_value_part(FrameKind::Response as u8, &response, &mut encoded);
        write_bytes(&mut self.writer, Bytes::from(encoded)).await?;
        finish_bytes(&mut self.writer).await
    }

    pub fn reset(mut self, code: ResetCode) {
        DropResetWrite::reset(&mut self.writer, code);
    }
}

pub(crate) async fn handle_progress_inner<S, M, St, H, HF, E>(
    state: S,
    context: Context,
    config: RouterConfig,
    mut reader: St::Reader,
    writer: St::Writer,
    handle: H,
    handle_error: E,
) where
    M: Progress + 'static,
    St: RpcStream + 'static,
    H: FnOnce(S, Context, M::Request, ProgressResponder<M, St::Writer>) -> HF,
    HF: Future<Output = ()>,
    E: FnOnce(&S, &RpcError<M::Error, St::Error>),
{
    let request = match read_framed_request::<M::Request, _>(&mut reader, config).await {
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

    handle(
        state,
        context,
        request,
        ProgressResponder {
            writer: DropResetWrite::new(writer),
            marker: PhantomData,
        },
    )
    .await;
}
