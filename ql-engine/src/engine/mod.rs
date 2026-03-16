mod implementation;
pub mod replay_cache;
mod sink;
mod state;
#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};

pub use sink::EngineEventSink;
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

    pub fn open_stream(
        &mut self,
        now: Instant,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
        config: StreamConfig,
    ) -> Result<StreamId, QlError> {
        self.state.now = now;
        self.open_stream_inner(request_head, request_prefix, config)
    }

    pub fn bind_peer(&mut self, now: Instant, peer: Peer, events: &mut impl EngineEventSink) {
        self.state.now = now;
        self.bind_peer_inner(peer, events);
    }

    pub fn pair(&mut self, now: Instant, crypto: &impl QlCrypto) {
        self.state.now = now;
        self.pair_inner(crypto);
    }

    pub fn connect(
        &mut self,
        now: Instant,
        crypto: &impl QlCrypto,
        events: &mut impl EngineEventSink,
    ) {
        self.state.now = now;
        self.connect_inner(crypto, events);
    }

    pub fn unpair(&mut self, now: Instant, events: &mut impl EngineEventSink) {
        self.state.now = now;
        self.unpair_inner(events);
    }

    pub fn take_next_write(
        &mut self,
        now: Instant,
        crypto: &impl QlCrypto,
    ) -> Option<OutboundWrite> {
        self.state.now = now;
        self.take_next_write_inner(crypto)
    }

    pub fn complete_write(
        &mut self,
        now: Instant,
        write_id: WriteId,
        result: Result<(), QlError>,
        events: &mut impl EngineEventSink,
    ) {
        self.state.now = now;
        self.complete_write_inner(write_id, result, events);
    }

    pub fn write_stream(
        &mut self,
        now: Instant,
        stream_id: StreamId,
        bytes: Vec<u8>,
    ) -> Result<(), QlError> {
        self.state.now = now;
        self.write_stream_inner(stream_id, bytes)
    }

    pub fn finish_stream(&mut self, now: Instant, stream_id: StreamId) -> Result<(), QlError> {
        self.state.now = now;
        self.finish_stream_inner(stream_id)
    }

    pub fn close_stream(
        &mut self,
        now: Instant,
        stream_id: StreamId,
        target: CloseTarget,
        code: CloseCode,
        payload: Vec<u8>,
    ) -> Result<(), QlError> {
        self.state.now = now;
        self.close_stream_inner(stream_id, target, code, payload)
    }

    pub fn receive(
        &mut self,
        now: Instant,
        bytes: Vec<u8>,
        crypto: &impl QlCrypto,
        events: &mut impl EngineEventSink,
    ) {
        self.state.now = now;
        self.receive_inner(bytes, crypto, events);
    }

    pub fn on_timer(
        &mut self,
        now: Instant,
        crypto: &impl QlCrypto,
        events: &mut impl EngineEventSink,
    ) {
        self.state.now = now;
        self.on_timer_inner(crypto, events);
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.next_deadline_inner()
    }

    pub fn abort(&mut self, now: Instant, error: QlError, events: &mut impl EngineEventSink) {
        self.state.now = now;
        self.abort_inner(error, events);
    }
}
