pub use handle::{
    AcceptedCall, CallResponder, InboundByteStream, InboundCall, OutboundByteStream, PendingAccept,
    PendingCall, RuntimeHandle,
};
pub use internal::{InitiatorStage, PeerSession, Token};

mod core;
pub mod handle;
pub(crate) mod internal;
pub mod replay_cache;

use std::time::Duration;

use bc_components::XID;

use crate::{platform::QlPlatform, CallId};

#[derive(Debug, Clone, Copy)]
pub struct CallConfig {
    pub open_timeout: Option<Duration>,
}

impl Default for CallConfig {
    fn default() -> Self {
        Self { open_timeout: None }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct KeepAliveConfig {
    pub interval: Duration,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeConfig {
    pub handshake_timeout: Duration,
    pub default_open_timeout: Duration,
    pub packet_expiration: Duration,
    pub packet_ack_timeout: Duration,
    pub call_retry_limit: u8,
    pub max_payload_bytes: usize,
    pub pipe_size_bytes: usize,
    pub initial_credit: u64,
    pub keep_alive: Option<KeepAliveConfig>,
}

impl RuntimeConfig {
    pub fn new(handshake_timeout: Duration) -> Self {
        Self {
            handshake_timeout,
            default_open_timeout: Duration::from_secs(5),
            packet_expiration: Duration::from_secs(30),
            packet_ack_timeout: Duration::from_millis(150),
            call_retry_limit: 5,
            max_payload_bytes: 1024,
            pipe_size_bytes: 2048,
            initial_credit: 1024,
            keep_alive: None,
        }
    }

    pub fn with_open_timeout(mut self, timeout: Duration) -> Self {
        self.default_open_timeout = timeout;
        self
    }

    pub fn with_packet_expiration(mut self, expiration: Duration) -> Self {
        self.packet_expiration = expiration;
        self
    }

    pub fn with_packet_ack_timeout(mut self, timeout: Duration) -> Self {
        self.packet_ack_timeout = timeout;
        self
    }

    pub fn with_call_retry_limit(mut self, call_retry_limit: u8) -> Self {
        self.call_retry_limit = call_retry_limit;
        self
    }

    pub fn with_max_payload_bytes(mut self, max_payload_bytes: usize) -> Self {
        self.max_payload_bytes = max_payload_bytes.max(1);
        self.initial_credit = self.initial_credit.max(self.max_payload_bytes as u64);
        self.pipe_size_bytes = self.pipe_size_bytes.max(self.max_payload_bytes);
        self
    }

    pub fn with_pipe_size_bytes(mut self, pipe_size_bytes: usize) -> Self {
        self.pipe_size_bytes = pipe_size_bytes.max(self.max_payload_bytes);
        self
    }

    pub fn with_initial_credit(mut self, initial_credit: u64) -> Self {
        self.initial_credit = initial_credit.max(self.max_payload_bytes as u64);
        self
    }

    pub fn with_keep_alive(mut self, config: KeepAliveConfig) -> Self {
        self.keep_alive = Some(config);
        self
    }
}

#[derive(Debug)]
pub enum HandlerEvent {
    Call(InboundCall),
}

pub(crate) struct AcceptedCallDelivery {
    pub peer: XID,
    pub call_id: CallId,
    pub response_head: Vec<u8>,
    pub rx: async_channel::Receiver<internal::InboundStreamItem>,
    pub tx: async_channel::Sender<internal::RuntimeCommand>,
}

pub struct Runtime<P> {
    platform: P,
    config: RuntimeConfig,
    rx: async_channel::Receiver<internal::RuntimeCommand>,
    tx: async_channel::WeakSender<internal::RuntimeCommand>,
}

pub fn new_runtime<P>(platform: P, config: RuntimeConfig) -> (Runtime<P>, RuntimeHandle)
where
    P: QlPlatform,
{
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
