//! sync finite state machine for QuantumLink protocol
//!
//! a caller drives `QlFsm` inside its own event loop
//!
//! inputs to that loop usually include
//! - app actions like `bind_peer`, `connect_ik`, `connect_kk`, `connect_xx`, `open_stream`, or
//!   `stream`
//! - inbound transport bytes passed to `receive`
//! - a deadline expiring, handled by calling `on_timer`
//! - transport write results passed to `complete_write`
//!
//! outputs from `QlFsm` are
//! - outbound session and handshake records from `take_next_write`
//! - queued `Event`s returned by `poll_event` after `connect_ik`, `connect_kk`,
//!   `connect_xx`, `receive`, and `on_timer`
//! - stream callbacks on `StreamMeta`
//!
//! call `next_deadline` after handling current inputs and any queued outputs
//! use it to decide how long the outer loop can wait before `on_timer` must run
//! another input may arrive before that deadline, which is fine

mod error;
mod fsm;
mod handshake;
mod pairing;
mod session;
pub(crate) mod state;
#[cfg(test)]
mod tests;

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

pub use bytes::Bytes;
pub use error::*;
pub use pairing::PairingInvite;
use ql_common::{ResetCode, StreamId};
use ql_wire::{PairingToken, PeerBundle, QlCrypto, QlIdentity, SessionClose, SessionCloseCode};
pub use session::{SessionConfig, StreamIo, StreamOps, StreamReader, StreamWriter};

use crate::state::{LinkState, QlFsmState};

/// connection state for the bound peer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStatus {
    /// no active encrypted session
    Disconnected,
    /// we are driving the handshake
    Initiator,
    /// the encrypted session is up
    Connected,
    /// the bound peer was forgotten immediately
    ///
    /// unpair is abortive and best-effort. the binding is removed immediately
    /// and one final write may remain: a record containing only `SessionFrame::Unpair`
    Unpaired,
}

/// events emitted by `QlFsm`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// a peer was learned during handshake completion
    NewPeer,
    /// the peer changed lifecycle state
    PeerStatusChanged(PeerStatus),
    /// the peer opened a stream
    ///
    /// the stream may already be gone when this event is polled
    Opened(StreamId),
    /// the encrypted session was closed
    ///
    /// session close is abortive and best-effort. the session ends immediately
    /// one final write remains: a record containing only `SessionFrame::Close`
    /// the FSM does not wait for an ack for that record
    SessionClosed(SessionClose),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamResetEvent {
    pub stream_id: StreamId,
    pub code: ResetCode,
    pub target: StreamResetTarget,
    pub origin: ResetOrigin,
}

/// source of a stream reset
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResetOrigin {
    Local,
    Peer,
}

/// local stream halves that can be reset
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamResetTarget {
    Reader,
    Writer,
    Both,
}

impl StreamResetTarget {
    #[inline]
    pub fn reader(self) -> bool {
        matches!(self, Self::Reader | Self::Both)
    }

    #[inline]
    pub fn writer(self) -> bool {
        matches!(self, Self::Writer | Self::Both)
    }
}

/// handle for a session write returned by `QlFsm::take_next_write`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WriteId(pub(crate) u64);

/// outbound record produced by `QlFsm`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundWrite {
    /// wire bytes to hand to the transport
    pub record: Vec<u8>,
    /// write handle that must be completed exactly once
    pub write_id: Option<WriteId>,
}

/// application state stored with each protocol stream
pub trait StreamMeta: Default {
    /// handles newly readable bytes
    fn on_readable(&mut self, stream: StreamIo<'_>);

    /// handles newly available write capacity
    fn on_writable(&mut self, stream: StreamIo<'_>);

    /// handles the peer finishing its write side
    fn on_inbound_finished(&mut self, stream: StreamIo<'_>);

    /// handles acknowledgement of the local finish
    fn on_outbound_finished(&mut self, stream_id: StreamId);

    /// handles a stream reset
    fn on_reset(&mut self, reset: StreamResetEvent);
}

impl StreamMeta for () {
    fn on_readable(&mut self, _: StreamIo<'_>) {}

    fn on_writable(&mut self, _: StreamIo<'_>) {}

    fn on_inbound_finished(&mut self, _: StreamIo<'_>) {}

    fn on_outbound_finished(&mut self, _: StreamId) {}

    fn on_reset(&mut self, _: StreamResetEvent) {}
}

/// current state of one stream half
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamStatus {
    Open,
    Finished,
    Reset(ResetCode),
}

/// timing and buffering knobs for `QlFsm`
#[derive(Debug, Clone, Copy)]
pub struct QlFsmConfig {
    /// overall time limit for one handshake attempt
    pub handshake_timeout: Duration,
    pub session: SessionConfig,
}

impl Default for QlFsmConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
            session: SessionConfig::default(),
        }
    }
}

/// synchronous driver for peer binding, handshake, and encrypted streams
pub struct QlFsm<M: StreamMeta> {
    config: QlFsmConfig,
    identity: QlIdentity,
    state: QlFsmState<M>,
    events: VecDeque<Event>,
}

impl<M: StreamMeta> QlFsm<M> {
    /// creates a new `QlFsm`
    pub fn new(config: QlFsmConfig, identity: QlIdentity, now: Instant) -> Self {
        Self {
            config,
            identity,
            state: QlFsmState {
                next_control_id: 1,
                peer: None,
                armed_pairing_token: None,
                handshake: None,
                link: LinkState::Idle,
                now,
            },
            events: VecDeque::new(),
        }
    }

    /// binds the remote peer
    pub fn bind_peer(&mut self, peer: PeerBundle) {
        fsm::handle_bind_peer(self, peer);
    }

    /// returns the currently bound peer, if any
    pub fn peer(&self) -> Option<&PeerBundle> {
        self.state.peer.as_ref()
    }

    /// arms acceptance of inbound xx pairings for a single token
    pub fn arm_pairing(&mut self, token: PairingToken) {
        self.state.armed_pairing_token = Some(token);
    }

    pub fn pairing_token(&self) -> Option<&PairingToken> {
        self.state.armed_pairing_token.as_ref()
    }

    /// disarms inbound xx pairing and rejects any in-flight inbound xx responder state
    pub fn disarm_pairing(&mut self) {
        fsm::handle_disarm_pairing(self);
    }

    /// starts an outbound xx handshake using a pairing invite
    pub fn connect_xx(&mut self, now: Instant, invite: PairingInvite, crypto: &impl QlCrypto) {
        self.state.now = now;
        fsm::handle_connect_xx(self, invite, crypto);
    }

    /// starts an IK handshake with the currently bound peer
    pub fn connect_ik(&mut self, now: Instant, crypto: &impl QlCrypto) -> Result<(), NoPeerError> {
        self.state.now = now;
        fsm::handle_connect_ik(self, crypto)
    }

    /// starts a KK handshake with the currently bound peer
    pub fn connect_kk(&mut self, now: Instant, crypto: &impl QlCrypto) -> Result<(), NoPeerError> {
        self.state.now = now;
        fsm::handle_connect_kk(self, crypto)
    }

    /// handles one inbound wire message
    pub fn receive(
        &mut self,
        now: Instant,
        bytes: Vec<u8>,
        crypto: &impl QlCrypto,
    ) -> Result<(), ReceiveError> {
        self.state.now = now;
        fsm::receive(self, bytes, crypto)
    }

    /// returns the next queued event, if any
    pub fn poll_event(&mut self) -> Option<Event> {
        fsm::poll_event(self)
    }

    /// advances time-based state
    pub fn on_timer(&mut self, now: Instant) {
        self.state.now = now;
        fsm::on_timer(self);
    }

    /// returns the next timer deadline, if any
    pub fn next_deadline(&self) -> Option<Instant> {
        fsm::next_deadline(self)
    }

    pub fn has_shutdown_work(&self) -> bool {
        self.state
            .link
            .connected()
            .is_some_and(|state| state.session.has_shutdown_work())
    }

    /// returns the next outbound record
    ///
    /// if `write_id` is `Some`, call `complete_write` exactly once
    ///
    /// if it is `None`, the record is fire-and-forget
    pub fn take_next_write(
        &mut self,
        now: Instant,
        crypto: &impl QlCrypto,
    ) -> Option<OutboundWrite> {
        self.state.now = now;
        fsm::take_next_write(self, crypto)
    }

    /// completes a `SessionWriteId` from `take_next_write` with the transport outcome
    ///
    /// call this at most once for each returned `SessionWriteId`
    pub fn complete_write(&mut self, now: Instant, write_id: WriteId, success: bool) {
        self.state.now = now;
        fsm::complete_write(self, write_id, success);
    }

    /// closes the current encrypted session locally
    pub fn close_session(&mut self, code: SessionCloseCode) {
        fsm::close_session(self, code);
    }

    /// forgets the bound peer locally and may emit one final outbound `SessionFrame::Unpair`
    pub fn unpair(&mut self) {
        fsm::unpair(self);
    }

    /// opens a new outgoing stream
    pub fn open_stream(&mut self, header: Box<[u8]>) -> Result<StreamOps<'_, M>, NoSessionError> {
        fsm::open_stream(self, header)
    }

    /// returns an open stream
    pub fn stream(&mut self, stream_id: StreamId) -> Result<StreamOps<'_, M>, StreamError> {
        fsm::stream(self, stream_id)
    }

    /// queues a ping on the active session
    pub fn queue_ping(&mut self) -> Result<(), NoSessionError> {
        fsm::queue_ping(self)
    }
}
