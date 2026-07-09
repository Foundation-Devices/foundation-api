pub use ql_fsm::{NoSessionError, PairingInvite};

pub use self::{
    error::{QlStreamError, ResetOrigin},
    handle::*,
    platform::*,
};

pub(crate) mod command;
pub(crate) mod driver;
mod error;
pub mod handle;
pub(crate) mod io;
pub mod log;
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
    pub max_concurrent_message_writes: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            fsm: QlFsmConfig::default(),
            max_concurrent_message_writes: 4,
        }
    }
}

pub struct Runtime<P> {
    identity: QlIdentity,
    platform: P,
    config: RuntimeConfig,
    rx: async_channel::Receiver<command::Command>,
    tx: async_channel::Sender<command::Command>,
}

pub fn new_runtime<P>(
    identity: QlIdentity,
    platform: P,
    config: RuntimeConfig,
) -> (Runtime<P>, RuntimeHandle)
where
    P: QlPlatform,
{
    let (tx, rx) = async_channel::unbounded();
    let handle = RuntimeHandle::new(tx.clone());
    (
        Runtime {
            identity,
            platform,
            config,
            rx,
            tx,
        },
        handle,
    )
}
