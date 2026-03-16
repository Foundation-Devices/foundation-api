mod implementation;
pub mod replay_cache;
mod state;
#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};

use bc_components::XID;
pub use state::{
    Engine, EngineState, HandshakeInitiator, HandshakeResponder, KeepAliveState, OutboundWrite,
    PeerRecord, PeerSession, RecentReady, Token, WriteId,
};

use crate::{
    identity::QlIdentity,
    stream,
    wire::stream::{BodyChunk, CloseCode, CloseTarget},
    Peer, QlError, StreamId,
};

pub trait QlCrypto {
    fn fill_random_bytes(&self, data: &mut [u8]);
}

#[derive(Debug, Clone, Copy)]
pub struct KeepAliveConfig {
    pub interval: Duration,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StreamConfig {}

#[derive(Debug, Clone, Copy)]
pub struct EngineConfig {
    pub handshake_timeout: Duration,
    pub handshake_retry_interval: Duration,
    pub max_handshake_retries: u8,
    pub packet_expiration: Duration,
    pub stream_ack_delay: Duration,
    pub stream_ack_timeout: Duration,
    pub stream_fast_retransmit_threshold: u8,
    pub stream_retry_limit: u8,
    pub keep_alive: Option<KeepAliveConfig>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
            handshake_retry_interval: Duration::from_millis(750),
            max_handshake_retries: 3,
            packet_expiration: Duration::from_secs(30),
            stream_ack_delay: Duration::from_millis(5),
            stream_ack_timeout: Duration::from_millis(150),
            stream_fast_retransmit_threshold: 2,
            stream_retry_limit: 5,
            keep_alive: None,
        }
    }
}

#[derive(Debug)]
pub enum EngineInput {
    BindPeer(Peer),
    Pair,
    Connect,
    Unpair,
    CloseStream {
        stream_id: StreamId,
        target: CloseTarget,
        code: CloseCode,
        payload: Vec<u8>,
    },

    OutboundData {
        stream_id: StreamId,
        bytes: Vec<u8>,
    },
    OutboundFinished {
        stream_id: StreamId,
    },
    Incoming(Vec<u8>),
    TimerExpired,
}

#[derive(Debug)]
pub enum EngineOutput {
    PeerStatusChanged {
        peer: XID,
        session: PeerSession,
    },
    PersistPeer(Peer),
    ClearPeer,

    InboundStreamOpened {
        stream_id: StreamId,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
    },
    InboundData {
        stream_id: StreamId,
        bytes: Vec<u8>,
    },
    InboundFinished {
        stream_id: StreamId,
    },
    InboundFailed {
        stream_id: StreamId,
        error: QlError,
    },

    OutboundClosed {
        stream_id: StreamId,
    },
    OutboundFailed {
        stream_id: StreamId,
        error: QlError,
    },

    StreamReaped {
        stream_id: StreamId,
    },
}

pub trait OutputFn: FnMut(EngineOutput) {}

impl<T> OutputFn for T where T: FnMut(EngineOutput) {}

impl Engine {
    pub fn new(config: EngineConfig, identity: QlIdentity, peer: Option<Peer>) -> Self {
        let local_namespace = peer
            .as_ref()
            .map(|peer| stream::StreamNamespace::for_local(identity.xid, peer.peer))
            .map(|namespace| match namespace {
                stream::StreamNamespace::Low => crate::stream::StreamNamespace::Low,
                stream::StreamNamespace::High => crate::stream::StreamNamespace::High,
            })
            .unwrap_or(crate::stream::StreamNamespace::Low);
        Self {
            config: config,
            identity,
            peer: peer
                .map(|peer| PeerRecord::new(peer.peer, peer.signing_key, peer.encapsulation_key)),
            state: EngineState::new(),
            streams: stream::StreamFsm::new(stream::StreamFsmConfig {
                local_namespace,
                ack_delay: config.stream_ack_delay,
                ack_timeout: config.stream_ack_timeout,
                fast_retransmit_threshold: config.stream_fast_retransmit_threshold,
                retry_limit: config.stream_retry_limit,
            }),
        }
    }

    pub fn run_tick(
        &mut self,
        now: Instant,
        input: EngineInput,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        self.run_tick_inner(now, input, crypto, emit);
    }

    pub fn take_next_write(&mut self, crypto: &impl QlCrypto) -> Option<OutboundWrite> {
        self.take_next_write_inner(crypto)
    }

    pub fn complete_write(
        &mut self,
        write_id: WriteId,
        result: Result<(), QlError>,
        emit: &mut impl OutputFn,
    ) {
        self.complete_write_inner(write_id, result, emit);
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.next_deadline_inner()
    }
}
