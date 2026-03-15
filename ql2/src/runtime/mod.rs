pub use handle::{
    DuplexStream, InboundByteStream, InboundStream, OutboundByteStream, RuntimeHandle,
};

pub use crate::engine::{EngineConfig, InitiatorStage, KeepAliveConfig, PeerSession, StreamConfig};

pub(crate) mod command;
pub(crate) mod driver;
pub mod handle;
pub mod platform;

// #[cfg(test)]
// mod tests;

use crate::{
    identity::QlIdentity,
    StreamId,
};

use self::platform::QlPlatform;

#[derive(Debug, Clone, Copy)]
pub struct RuntimeConfig {
    pub engine: EngineConfig,
    pub stream_send_buffer_bytes: usize,
    pub max_concurrent_message_writes: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            engine: EngineConfig::default(),
            stream_send_buffer_bytes: 64 * 1024,
            max_concurrent_message_writes: 4,
        }
    }
}

impl RuntimeConfig {
    pub(crate) fn normalized(mut self) -> Self {
        self.stream_send_buffer_bytes = self.stream_send_buffer_bytes.max(1);
        self.max_concurrent_message_writes = self.max_concurrent_message_writes.max(1);
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

pub(crate) struct OpenedStreamDelivery {
    pub stream_id: StreamId,
    pub response: async_channel::Receiver<InboundEvent>,
}

pub struct Runtime<P> {
    identity: QlIdentity,
    platform: P,
    config: RuntimeConfig,
    rx: async_channel::Receiver<command::RuntimeCommand>,
    tx: async_channel::WeakSender<command::RuntimeCommand>,
}

pub fn new_runtime<P>(
    identity: QlIdentity,
    platform: P,
    config: RuntimeConfig,
) -> (Runtime<P>, RuntimeHandle)
where
    P: QlPlatform,
{
    let config = config.normalized();
    let (tx, rx) = async_channel::unbounded();
    (
        Runtime {
            identity,
            platform,
            config,
            rx,
            tx: tx.downgrade(),
        },
        RuntimeHandle {
            tx,
            stream_send_buffer_bytes: config.stream_send_buffer_bytes,
        },
    )
}
