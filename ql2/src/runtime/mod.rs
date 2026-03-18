pub use handle::{
    AcceptedStream, InboundByteStream, InboundStream, OutboundByteStream, PendingAccept,
    PendingStream, RuntimeHandle, StreamResponder,
};

pub use crate::engine::{
    EngineConfig, InitiatorStage, KeepAliveConfig, PeerSession, StreamConfig, Token,
};

pub(crate) mod command;
pub(crate) mod driver;
pub mod handle;

use crate::{platform::QlPlatform, StreamId};

#[derive(Debug, Clone, Copy)]
pub struct RuntimeConfig {
    pub engine: EngineConfig,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            engine: EngineConfig::default(),
        }
    }
}

impl RuntimeConfig {
    pub(crate) fn normalized(mut self) -> Self {
        self.engine = self.engine.normalized();
        self
    }
}

#[derive(Debug)]
pub enum HandlerEvent {
    Stream(InboundStream),
}

#[derive(Debug)]
pub(crate) enum InboundEvent {
    Data(Vec<u8>),
    Finished,
    Failed(crate::QlError),
}

pub(crate) struct AcceptedStreamDelivery {
    pub stream_id: StreamId,
    pub response_head: Vec<u8>,
    pub response: async_channel::Receiver<InboundEvent>,
    pub tx: async_channel::Sender<command::RuntimeCommand>,
}

pub struct Runtime<P> {
    platform: P,
    config: RuntimeConfig,
    rx: async_channel::Receiver<command::RuntimeCommand>,
    tx: async_channel::WeakSender<command::RuntimeCommand>,
}

pub fn new_runtime<P>(platform: P, config: RuntimeConfig) -> (Runtime<P>, RuntimeHandle)
where
    P: QlPlatform,
{
    let config = config.normalized();
    let (tx, rx) = async_channel::unbounded();
    (
        Runtime {
            platform,
            config,
            rx,
            tx: tx.downgrade(),
        },
        RuntimeHandle { tx },
    )
}
