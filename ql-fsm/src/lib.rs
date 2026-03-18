mod error;
pub(crate) mod implementation;
pub(crate) mod replay_cache;
mod session;
pub(crate) mod state;
#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};

pub use error::QlFsmError;
use ql_wire::{
    CloseCode, CloseTarget, MlDsaPublicKey, MlKemPublicKey, QlCrypto, QlIdentity, QlRecord,
    SessionCloseBody, SessionSeq, StreamClose, StreamId, XID,
};

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
    pub signing_key: MlDsaPublicKey,
    pub encapsulation_key: MlKemPublicKey,
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
    Closed(StreamClose),
    WritableClosed(StreamId),
    Unpaired,
    SessionClosed(SessionCloseBody),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionWriteId(pub SessionSeq);

#[derive(Debug, Clone, PartialEq)]
pub struct OutboundWrite {
    pub record: QlRecord,
    pub session_write_id: Option<SessionWriteId>,
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

pub struct QlFsm {
    pub config: QlFsmConfig,
    pub identity: QlIdentity,
    pub(crate) peer: Option<PeerRecord>,
    pub(crate) session: SessionFsm,
    pub(crate) state: QlFsmState,
}

impl QlFsm {
    pub fn new(config: QlFsmConfig, identity: QlIdentity, now: FsmTime) -> Self {
        Self {
            config,
            identity,
            peer: None,
            session: session::SessionFsm::new(
                session::SessionFsmConfig {
                    local_namespace: session::StreamNamespace::Low,
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
        implementation::handle_bind_peer(self, peer);
    }

    pub fn pair(&mut self, now: FsmTime, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
        self.state.now = now;
        implementation::handle_pair_local(self, crypto)
    }

    pub fn connect(&mut self, now: FsmTime, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
        self.state.now = now;
        implementation::handle_connect(self, crypto)
    }

    pub fn receive(
        &mut self,
        now: FsmTime,
        bytes: Vec<u8>,
        crypto: &impl QlCrypto,
    ) -> Result<(), QlFsmError> {
        self.state.now = now;
        implementation::receive(self, bytes, crypto)
    }

    pub fn on_timer(&mut self, now: FsmTime) {
        self.state.now = now;
        implementation::on_timer(self);
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        implementation::next_deadline(self)
    }

    /// Returns the next outbound record.
    ///
    /// If `session_write_id` is `Some`, it must be followed by exactly one of
    /// [`Self::confirm_session_write`] or [`Self::return_session_write`].
    ///
    /// If `session_write_id` is `None`, the record is fire-and-forget.
    pub fn take_next_write(
        &mut self,
        now: FsmTime,
        crypto: &impl QlCrypto,
    ) -> Option<OutboundWrite> {
        self.state.now = now;
        implementation::take_next_write(self, crypto)
    }

    /// Marks a previously issued session write as successfully handed to the transport.
    ///
    /// This must be called at most once for a `SessionWriteId` returned by
    /// [`Self::take_next_write`] whose `session_write_id` was `Some`.
    pub fn confirm_session_write(&mut self, now: FsmTime, write_id: SessionWriteId) {
        self.state.now = now;
        implementation::confirm_session_write(self, write_id);
    }

    /// Reports that a previously issued session write was not accepted by the transport.
    ///
    /// This must be called at most once for a `SessionWriteId` returned by
    /// [`Self::take_next_write`] whose `session_write_id` was `Some`.
    pub fn reject_session_write(&mut self, write_id: SessionWriteId) {
        implementation::return_session_write(self, write_id);
    }

    /// Aborts the current encrypted session locally.
    pub fn kill_session(&mut self, code: CloseCode) {
        implementation::kill_session(self, code);
    }

    pub fn take_next_event(&mut self) -> Option<QlFsmEvent> {
        implementation::take_next_event(self)
    }

    pub fn open_stream(&mut self) -> Result<StreamId, QlFsmError> {
        implementation::open_stream(self)
    }

    pub fn write_stream(&mut self, stream_id: StreamId, bytes: Vec<u8>) -> Result<(), QlFsmError> {
        implementation::write_stream(self, stream_id, bytes)
    }

    pub fn finish_stream(&mut self, stream_id: StreamId) -> Result<(), QlFsmError> {
        implementation::finish_stream(self, stream_id)
    }

    pub fn close_stream(
        &mut self,
        stream_id: StreamId,
        target: CloseTarget,
        code: CloseCode,
        payload: Vec<u8>,
    ) -> Result<(), QlFsmError> {
        implementation::close_stream(self, stream_id, target, code, payload)
    }

    pub fn queue_ping(&mut self) -> Result<(), QlFsmError> {
        implementation::queue_ping(self)
    }

    pub fn queue_unpair(&mut self) -> Result<(), QlFsmError> {
        implementation::queue_unpair(self)
    }

    pub fn take_next_session_event(&mut self) -> Option<QlSessionEvent> {
        implementation::take_next_session_event(self)
    }
}
