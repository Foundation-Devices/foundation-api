pub(crate) mod implementation;
pub(crate) mod replay_cache;
pub mod session;
pub(crate) mod state;
#[cfg(test)]
mod tests;

use std::time::Instant;

use ql_wire::{CloseCode, CloseTarget, QlCrypto, QlIdentity, QlRecord, StreamId};
pub use state::QlSessionEvent;
pub use state::{
    HandshakeInitiator, HandshakeResponder, Peer, PeerRecord, PeerSession, QlFsm, QlFsmConfig,
    QlFsmError, QlFsmEvent, RecentReady,
};

use crate::{replay_cache::ReplayCache, state::QlFsmState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsmTime {
    pub instant: Instant,
    pub unix_secs: u64,
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

    pub fn take_next_outbound(
        &mut self,
        now: FsmTime,
        crypto: &impl QlCrypto,
    ) -> Option<QlRecord> {
        self.state.now = now;
        self.take_next_outbound_inner(crypto)
    }

    pub fn take_next_event(&mut self) -> Option<QlFsmEvent> {
        self.take_next_event_inner()
    }

    pub fn open_stream(&mut self) -> Result<StreamId, session::StreamError> {
        if self
            .peer
            .as_ref()
            .and_then(|entry| entry.session.session_key())
            .is_none()
        {
            return Err(session::StreamError::SessionClosed);
        }
        self.session.open_stream()
    }

    pub fn write_stream(
        &mut self,
        stream_id: StreamId,
        bytes: Vec<u8>,
    ) -> Result<(), session::StreamError> {
        if self
            .peer
            .as_ref()
            .and_then(|entry| entry.session.session_key())
            .is_none()
        {
            return Err(session::StreamError::SessionClosed);
        }
        self.session.write_stream(stream_id, bytes)
    }

    pub fn finish_stream(&mut self, stream_id: StreamId) -> Result<(), session::StreamError> {
        if self
            .peer
            .as_ref()
            .and_then(|entry| entry.session.session_key())
            .is_none()
        {
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
        if self
            .peer
            .as_ref()
            .and_then(|entry| entry.session.session_key())
            .is_none()
        {
            return Err(session::StreamError::SessionClosed);
        }
        self.session.close_stream(stream_id, target, code, payload)
    }

    pub fn queue_heartbeat(&mut self) -> Result<(), session::StreamError> {
        if self
            .peer
            .as_ref()
            .and_then(|entry| entry.session.session_key())
            .is_none()
        {
            return Err(session::StreamError::SessionClosed);
        }
        self.session.queue_heartbeat()
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
