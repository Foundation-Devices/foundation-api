use std::future::Future;

use crate::{
    duplex::{Duplex, DuplexReceiver, DuplexSender},
    Context, RpcRead, RpcStream, RpcWrite,
};

#[trait_variant::make(DuplexHandler: Send)]
pub trait DuplexHandlerLocal<M, St>
where
    M: Duplex,
    St: RpcStream,
{
    async fn handle(self, context: Context, peer: DuplexPeer<M, St::Writer, St::Reader>);
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

pub(crate) fn handle_duplex<S, M, St, H, HF>(
    state: S,
    context: Context,
    _config: crate::RouterConfig,
    stream: St,
    handle: H,
) -> impl Future<Output = ()>
where
    M: Duplex + 'static,
    St: RpcStream + 'static,
    H: FnOnce(S, Context, DuplexPeer<M, St::Writer, St::Reader>) -> HF,
    HF: Future<Output = ()>,
{
    let (reader, writer) = stream.split();

    async move {
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
}
