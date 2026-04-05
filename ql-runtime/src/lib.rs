pub use self::{error::QlError, handle::*, platform::*};

pub(crate) mod command;
pub(crate) mod driver;
mod error;
pub mod handle;
pub mod platform;
#[cfg(feature = "rpc")]
pub mod rpc;

#[cfg(test)]
mod tests;

use ql_fsm::QlFsmConfig;
use ql_wire::QlIdentity;

#[derive(Debug, Clone, Copy)]
pub struct RuntimeConfig {
    pub fsm: QlFsmConfig,
    pub stream_send_buffer_bytes: usize,
    pub max_concurrent_message_writes: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            fsm: QlFsmConfig::default(),
            stream_send_buffer_bytes: 16 * 1024,
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
        RuntimeHandle::new(tx, config.stream_send_buffer_bytes),
    )
}
