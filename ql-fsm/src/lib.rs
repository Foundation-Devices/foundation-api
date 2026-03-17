pub(crate) mod implementation;
pub(crate) mod replay_cache;
pub mod session;
pub(crate) mod state;
#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};

use bc_components::{MLDSAPublicKey, MLKEMPublicKey};
use ql_wire::{
    CloseCode, CloseTarget, QlCrypto, QlIdentity, QlRecord, SessionCloseBody, StreamCloseFrame,
    StreamId, WireError, XID,
};
use thiserror::Error;

use crate::{
    replay_cache::ReplayCache,
    session::SessionFsm,
    state::{PeerRecord, QlFsmState},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsmTime {
    pub instant: Instant,
    pub unix_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub xid: XID,
    pub signing_key: MLDSAPublicKey,
    pub encapsulation_key: MLKEMPublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStatus {
    Disconnected,
    Initiator,
    Responder,
    Connected,
}

#[derive(Debug, Clone)]
pub enum QlFsmEvent {
    NewPeer(Peer),
    ClearPeer,
    PeerStatusChanged { peer: XID, status: PeerStatus },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QlSessionEvent {
    Opened(StreamId),
    Data { stream_id: StreamId, bytes: Vec<u8> },
    Finished(StreamId),
    Closed(StreamCloseFrame),
    WritableClosed(StreamId),
    Unpaired,
    SessionClosed(SessionCloseBody),
}

#[derive(Debug, Clone, Copy)]
pub struct QlFsmConfig {
    pub handshake_timeout: Duration,
    pub handshake_retry_interval: Duration,
    pub max_handshake_retries: u8,
    pub control_expiration: Duration,
    pub session_ack_delay: Duration,
    pub session_retransmit_timeout: Duration,
    pub session_keepalive_interval: Duration,
    pub session_peer_timeout: Duration,
}

impl Default for QlFsmConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
            handshake_retry_interval: Duration::from_millis(750),
            max_handshake_retries: 3,
            control_expiration: Duration::from_secs(30),
            session_ack_delay: Duration::from_millis(5),
            session_retransmit_timeout: Duration::from_millis(150),
            session_keepalive_interval: Duration::from_secs(10),
            session_peer_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum QlFsmError {
    #[error("invalid payload")]
    InvalidPayload,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("expired")]
    Expired,
    #[error("no peer bound")]
    NoPeerBound,
}

impl From<WireError> for QlFsmError {
    fn from(value: WireError) -> Self {
        match value {
            WireError::InvalidPayload => Self::InvalidPayload,
            WireError::InvalidSignature => Self::InvalidSignature,
            WireError::Expired => Self::Expired,
        }
    }
}

pub struct QlFsm {
    pub config: QlFsmConfig,
    pub identity: QlIdentity,
    pub(crate) peer: Option<PeerRecord>,
    pub(crate) session: SessionFsm,
    pub(crate) state: QlFsmState,
}

impl QlFsm {
    pub fn new(
        config: QlFsmConfig,
        identity: QlIdentity,
        peer: Option<Peer>,
        now: FsmTime,
    ) -> Self {
        let peer = peer.map(PeerRecord::new);
        let local_namespace = peer
            .as_ref()
            .map(|peer| session::StreamNamespace::for_local(identity.xid, peer.peer.xid))
            .unwrap_or(session::StreamNamespace::Low);
        Self {
            config,
            identity,
            peer,
            session: session::SessionFsm::new(
                session::SessionFsmConfig {
                    local_namespace,
                    ack_delay: config.session_ack_delay,
                    retransmit_timeout: config.session_retransmit_timeout,
                    keepalive_interval: config.session_keepalive_interval,
                    peer_timeout: config.session_peer_timeout,
                },
                now.instant,
            ),
            state: QlFsmState {
                replay_cache: ReplayCache::default(),
                next_control_id: 1,
                outbound: Default::default(),
                events: Default::default(),
                session_events: Default::default(),
                now,
            },
        }
    }

    pub fn bind_peer(&mut self, peer: Peer) {
        self.bind_peer_inner(peer);
    }

    pub fn pair(&mut self, now: FsmTime, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
        self.state.now = now;
        self.pair_inner(crypto)
    }

    pub fn connect(&mut self, now: FsmTime, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
        self.state.now = now;
        self.connect_inner(crypto)
    }

    pub fn receive(
        &mut self,
        now: FsmTime,
        bytes: Vec<u8>,
        crypto: &impl QlCrypto,
    ) -> Result<(), QlFsmError> {
        self.state.now = now;
        self.receive_inner(bytes, crypto)
    }

    pub fn on_timer(&mut self, now: FsmTime) {
        self.state.now = now;
        self.on_timer_inner();
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.next_deadline_inner()
    }

    pub fn take_next_outbound(&mut self, now: FsmTime, crypto: &impl QlCrypto) -> Option<QlRecord> {
        self.state.now = now;
        self.take_next_outbound_inner(crypto)
    }

    pub fn take_next_event(&mut self) -> Option<QlFsmEvent> {
        self.take_next_event_inner()
    }

    pub fn open_stream(&mut self) -> Result<StreamId, session::StreamError> {
        if self.peer.is_none() {
            return Err(session::StreamError::SessionClosed);
        }
        self.session.open_stream()
    }

    pub fn write_stream(
        &mut self,
        stream_id: StreamId,
        bytes: Vec<u8>,
    ) -> Result<(), session::StreamError> {
        if self.peer.is_none() {
            return Err(session::StreamError::SessionClosed);
        }
        self.session.write_stream(stream_id, bytes)
    }

    pub fn finish_stream(&mut self, stream_id: StreamId) -> Result<(), session::StreamError> {
        if self.peer.is_none() {
            return Err(session::StreamError::SessionClosed);
        }
        self.session.finish_stream(stream_id)
    }

    pub fn close_stream(
        &mut self,
        stream_id: StreamId,
        target: CloseTarget,
        code: CloseCode,
        payload: Vec<u8>,
    ) -> Result<(), session::StreamError> {
        if self.peer.is_none() {
            return Err(session::StreamError::SessionClosed);
        }
        self.session.close_stream(stream_id, target, code, payload)
    }

    pub fn queue_ping(&mut self) -> Result<(), session::StreamError> {
        if self
            .peer
            .as_ref()
            .and_then(|entry| entry.session.session_key())
            .is_none()
        {
            return Err(session::StreamError::SessionClosed);
        }
        self.session.queue_ping()
    }

    pub fn queue_unpair(&mut self) -> Result<(), session::StreamError> {
        if self
            .peer
            .as_ref()
            .and_then(|entry| entry.session.session_key())
            .is_none()
        {
            return Err(session::StreamError::SessionClosed);
        }
        // TODO: keep local peer/session state alive until this queued unpair is acked or times out,
        // then clear it locally. Right now this only requests remote unpair.
        self.session.queue_unpair()
    }

    pub fn take_next_session_event(&mut self) -> Option<QlSessionEvent> {
        self.state.session_events.pop_front()
    }
}
