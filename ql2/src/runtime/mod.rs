pub use handle::{
    AcceptedStream, InboundByteStream, InboundStream, OutboundByteStream, PendingAccept,
    PendingStream, RuntimeHandle, StreamResponder,
};

pub use crate::engine::{EngineConfig, InitiatorStage, KeepAliveConfig, PeerSession, Token};

pub(crate) mod command;
pub(crate) mod driver;
pub mod handle;
pub(crate) mod pipe;

use std::time::Duration;

use crate::{platform::QlPlatform, StreamId};

#[derive(Debug, Clone, Copy, Default)]
pub struct StreamConfig {
    pub open_timeout: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeConfig {
    pub engine: EngineConfig,
    pub pipe_size_bytes: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            engine: EngineConfig::default(),
            pipe_size_bytes: 2048,
        }
    }
}

impl RuntimeConfig {
    pub(crate) fn normalized(mut self) -> Self {
        self.engine = self.engine.normalized();
        self.pipe_size_bytes = self.pipe_size_bytes.max(self.engine.max_payload_bytes);
        self
    }
}

#[derive(Debug)]
pub enum HandlerEvent {
    Stream(InboundStream),
}

pub(crate) struct AcceptedStreamDelivery {
    pub stream_id: StreamId,
    pub response_head: Vec<u8>,
    pub response: crate::runtime::pipe::PipeReader<crate::QlError>,
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
        RuntimeHandle {
            tx,
            pipe_size_bytes: config.pipe_size_bytes,
        },
    )
}
