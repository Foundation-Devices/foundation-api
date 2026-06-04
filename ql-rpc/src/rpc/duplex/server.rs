use std::future::Future;

use crate::{
    duplex::{Duplex, DuplexReceiver, DuplexSender},
    RpcRead, RpcStream, RpcWrite,
};

#[trait_variant::make(DuplexHandler: Send)]
pub trait DuplexHandlerLocal<M, St>
where
    M: Duplex,
    St: RpcStream,
{
    async fn handle(self, peer: DuplexPeer<M, St::Writer, St::Reader>);
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
    _config: crate::RouterConfig,
    reader: St::Reader,
    writer: St::Writer,
    handle: H,
) where
    M: Duplex + 'static,
    St: RpcStream + 'static,
    H: FnOnce(S, DuplexPeer<M, St::Writer, St::Reader>) -> HF,
    HF: Future<Output = ()>,
{
    handle(
        state,
        DuplexPeer {
            sender: DuplexSender::new(writer),
            receiver: DuplexReceiver::new(reader),
        },
    )
    .await;
}
