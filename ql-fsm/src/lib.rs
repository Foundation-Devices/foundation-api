pub(crate) mod implementation;
pub(crate) mod replay_cache;
pub mod session;
pub(crate) mod state;

use std::time::Instant;

use ql_wire::{QlCrypto, QlIdentity, QlRecord};
use state::{
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
        Self {
            config,
            identity,
            peer,
            state: QlFsmState {
                replay_cache: ReplayCache::default(),
                next_control_id: 1,
                outbound: Default::default(),
                events: Default::default(),
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

    pub fn take_next_outbound(&mut self) -> Option<QlRecord> {
        self.take_next_outbound_inner()
    }

    pub fn take_next_event(&mut self) -> Option<QlFsmEvent> {
        self.take_next_event_inner()
    }
}
