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

pub trait EngineEventSink {
    fn peer_status_changed(&mut self, peer: XID, session: PeerSession);

    fn persist_peer(&mut self, peer: Peer);

    fn clear_peer(&mut self);

    fn inbound_stream_opened(
        &mut self,
        stream_id: StreamId,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
    );

    fn inbound_data(&mut self, stream_id: StreamId, bytes: Vec<u8>);

    fn inbound_finished(&mut self, stream_id: StreamId);

    fn inbound_failed(&mut self, stream_id: StreamId, error: QlError);

    fn outbound_closed(&mut self, stream_id: StreamId);

    fn outbound_failed(&mut self, stream_id: StreamId, error: QlError);

    fn stream_reaped(&mut self, stream_id: StreamId);
}

impl EngineEventSink for () {
    fn peer_status_changed(&mut self, _peer: XID, _session: PeerSession) {}

    fn persist_peer(&mut self, _peer: Peer) {}

    fn clear_peer(&mut self) {}

    fn inbound_stream_opened(
        &mut self,
        _stream_id: StreamId,
        _request_head: Vec<u8>,
        _request_prefix: Option<BodyChunk>,
    ) {
    }

    fn inbound_data(&mut self, _stream_id: StreamId, _bytes: Vec<u8>) {}

    fn inbound_finished(&mut self, _stream_id: StreamId) {}

    fn inbound_failed(&mut self, _stream_id: StreamId, _error: QlError) {}

    fn outbound_closed(&mut self, _stream_id: StreamId) {}

    fn outbound_failed(&mut self, _stream_id: StreamId, _error: QlError) {}

    fn stream_reaped(&mut self, _stream_id: StreamId) {}
}

impl EngineEventSink for Vec<EngineOutput> {
    fn peer_status_changed(&mut self, peer: XID, session: PeerSession) {
        self.push(EngineOutput::PeerStatusChanged { peer, session });
    }

    fn persist_peer(&mut self, peer: Peer) {
        self.push(EngineOutput::PersistPeer(peer));
    }

    fn clear_peer(&mut self) {
        self.push(EngineOutput::ClearPeer);
    }

    fn inbound_stream_opened(
        &mut self,
        stream_id: StreamId,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
    ) {
        self.push(EngineOutput::InboundStreamOpened {
            stream_id,
            request_head,
            request_prefix,
        });
    }

    fn inbound_data(&mut self, stream_id: StreamId, bytes: Vec<u8>) {
        self.push(EngineOutput::InboundData { stream_id, bytes });
    }

    fn inbound_finished(&mut self, stream_id: StreamId) {
        self.push(EngineOutput::InboundFinished { stream_id });
    }

    fn inbound_failed(&mut self, stream_id: StreamId, error: QlError) {
        self.push(EngineOutput::InboundFailed { stream_id, error });
    }

    fn outbound_closed(&mut self, stream_id: StreamId) {
        self.push(EngineOutput::OutboundClosed { stream_id });
    }

    fn outbound_failed(&mut self, stream_id: StreamId, error: QlError) {
        self.push(EngineOutput::OutboundFailed { stream_id, error });
    }

    fn stream_reaped(&mut self, stream_id: StreamId) {
        self.push(EngineOutput::StreamReaped { stream_id });
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

    pub fn bind_peer(&mut self, peer: Peer, events: &mut impl EngineEventSink) {
        self.bind_peer_inner(peer, events);
    }

    pub fn pair(&mut self, now: Instant, crypto: &impl QlCrypto) {
        self.pair_inner(now, crypto);
    }

    pub fn connect(
        &mut self,
        now: Instant,
        crypto: &impl QlCrypto,
        events: &mut impl EngineEventSink,
    ) {
        self.connect_inner(now, crypto, events);
    }

    pub fn unpair(&mut self, now: Instant, events: &mut impl EngineEventSink) {
        self.unpair_inner(now, events);
    }

    pub fn take_next_write(&mut self, crypto: &impl QlCrypto) -> Option<OutboundWrite> {
        self.take_next_write_inner(crypto)
    }

    pub fn complete_write(
        &mut self,
        write_id: WriteId,
        result: Result<(), QlError>,
        events: &mut impl EngineEventSink,
    ) {
        self.complete_write_inner(write_id, result, events);
    }

    pub fn write_stream(&mut self, stream_id: StreamId, bytes: Vec<u8>) -> Result<(), QlError> {
        self.write_stream_inner(stream_id, bytes)
    }

    pub fn finish_stream(&mut self, stream_id: StreamId) -> Result<(), QlError> {
        self.finish_stream_inner(stream_id)
    }

    pub fn close_stream(
        &mut self,
        stream_id: StreamId,
        target: CloseTarget,
        code: CloseCode,
        payload: Vec<u8>,
    ) -> Result<(), QlError> {
        self.close_stream_inner(stream_id, target, code, payload)
    }

    pub fn receive(
        &mut self,
        now: Instant,
        bytes: Vec<u8>,
        crypto: &impl QlCrypto,
        events: &mut impl EngineEventSink,
    ) {
        self.receive_inner(now, bytes, crypto, events);
    }

    pub fn on_timer(
        &mut self,
        now: Instant,
        crypto: &impl QlCrypto,
        events: &mut impl EngineEventSink,
    ) {
        self.on_timer_inner(now, crypto, events);
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.next_deadline_inner()
    }

    pub fn abort(&mut self, error: QlError, events: &mut impl EngineEventSink) {
        self.abort_inner(error, events);
    }
}
