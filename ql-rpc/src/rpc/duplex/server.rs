use std::future::Future;

use crate::{
    duplex::{Duplex, DuplexReceiver, DuplexSender},
    Context, RpcError, RpcRead, RpcStream, RpcWrite,
};

#[trait_variant::make(DuplexHandler: Send)]
pub trait DuplexHandlerLocal<M, St>
where
    M: Duplex,
    St: RpcStream,
{
    async fn handle(self, context: Context, peer: DuplexPeer<M, St::Writer, St::Reader>);

    fn handle_error(&self, _error: &RpcError<M::Error, St::Error>) {}
}

pub struct DuplexPeer<M, W, R>
where
    M: Duplex,
    W: RpcWrite,
    R: RpcRead,
{
    pub sender: DuplexSender<M::ResponderEvent, W>,
    pub receiver: DuplexReceiver<M::InitiatorEvent, R>,
}

pub(crate) async fn handle_duplex_inner<S, M, St, H, HF>(
    state: S,
    context: Context,
    _config: crate::RouterConfig,
    reader: St::Reader,
    writer: St::Writer,
    handle: H,
) where
    M: Duplex + 'static,
    St: RpcStream + 'static,
    H: FnOnce(S, Context, DuplexPeer<M, St::Writer, St::Reader>) -> HF,
    HF: Future<Output = ()>,
{
    handle(
        state,
        context,
        DuplexPeer {
            sender: DuplexSender::new(writer),
            receiver: DuplexReceiver::new(reader),
        },
    )
    .await;
}
