//! sync finite state machine for quantum link protocol
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
//! - queued `QlFsmEvent`s returned by `poll_event` after `connect_ik`, `connect_kk`,
//!   `connect_xx`, `receive`, and `on_timer`
//!
//! call `next_deadline` after handling current inputs and any queued outputs
//! use it to decide how long the outer loop can wait before `on_timer` must run
//! another input may arrive before that deadline, which is fine

mod error;
mod fsm;
mod handshake;
pub(crate) mod replay_cache;
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
use ql_wire::{
    PairingToken, PeerBundle, QlCrypto, QlIdentity, RouteId, SessionClose, SessionCloseCode,
    StreamClose, StreamId,
};
pub use session::{SessionEvent, StreamReadIter, StreamWriter};

use crate::{
    replay_cache::ReplayCache,
    state::{LinkState, QlFsmState},
};

/// time input for `QlFsm`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsmTime {
    /// monotonic time used for local deadlines
    pub instant: Instant,
    /// wall-clock unix time used for expiration checks
    pub unix_secs: u64,
}

/// connection state for the bound peer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStatus {
    /// no active encrypted session
    Disconnected,
    /// we are driving the handshake
    Initiator,
    /// the encrypted session is up
    Connected,
}

/// events emitted by `QlFsm`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// a peer was learned during handshake completion
    NewPeer,
    /// the peer changed connection state
    PeerStatusChanged(PeerStatus),
    /// a stream was opened
    Opened {
        stream_id: StreamId,
        route_id: RouteId,
    },
    /// a stream has bytes ready to read
    Readable(StreamId),
    /// a stream has room for more local writes
    Writable(StreamId),
    /// the peer finished writing this stream and no more bytes remain to read
    Finished(StreamId),
    /// our local FIN was acknowledged by the peer at the session layer
    OutboundFinished(StreamId),
    /// a stream was closed
    Closed(StreamClose),
    /// local writes on this stream are closed
    WritableClosed(StreamClose),
    /// the encrypted session was closed
    ///
    /// session close is abortive and best-effort. the session ends immediately
    /// one final write remains: a record containing only `SessionFrame::Close`
    /// the FSM does not wait for an ack for that record
    SessionClosed(SessionClose),
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

pub struct StreamOps<'a> {
    inner: session::StreamOps<'a, fsm::FsmEventEmitter<'a>>,
}

impl StreamOps<'_> {
    /// returns this stream's identifier
    pub fn stream_id(&self) -> StreamId {
        self.inner.stream_id()
    }

    /// returns the readable stream bytes as owned `Bytes` views without consuming them
    pub fn read(&self) -> StreamReadIter<'_> {
        self.inner.read()
    }

    /// returns how many bytes can be read from the stream
    pub fn readable_bytes(&self) -> usize {
        self.inner.readable_bytes()
    }

    /// marks previously read bytes as consumed
    pub fn commit_read(&mut self, len: usize) -> Result<(), CommitReadError> {
        self.inner.commit_read(len)
    }

    /// returns a writer if the local write side is still open
    pub fn writer(&mut self) -> Option<StreamWriter<'_>> {
        self.inner.writer()
    }

    /// closes the origin lane, return lane, or both lanes of the stream
    pub fn close(&mut self, target: ql_wire::CloseTarget, code: ql_wire::StreamCloseCode) {
        self.inner.close(target, code);
    }
}

/// timing and buffering knobs for `QlFsm`
#[derive(Debug, Clone, Copy)]
pub struct QlFsmConfig {
    /// overall time limit for one handshake attempt
    pub handshake_timeout: Duration,
    /// delay before sending a pure record ack
    pub session_record_ack_delay: Duration,
    /// how long to wait before resending unacked session records
    pub session_record_retransmit_timeout: Duration,
    /// idle delay before sending a keepalive ping
    pub session_keepalive_interval: Duration,
    /// how long to wait before declaring the peer dead
    pub session_peer_timeout: Duration,
    /// maximum total wire size for one session record, including header and auth tag
    pub session_record_max_size: usize,
    /// maximum bytes buffered locally for one stream send side
    pub session_stream_send_buffer_size: usize,
    /// maximum bytes buffered locally for one stream receive side
    pub session_stream_receive_buffer_size: u32,
    /// how many accepted record sequence numbers to retain for duplicate detection
    pub session_accepted_record_window: u64,
    /// maximum disjoint pending ACK ranges to retain before dropping the oldest low ranges
    pub session_pending_ack_range_limit: usize,
}

impl Default for QlFsmConfig {
    fn default() -> Self {
        let s = session::SessionConfig::default();
        Self {
            handshake_timeout: Duration::from_secs(5),
            session_record_ack_delay: s.ack_delay,
            session_record_retransmit_timeout: s.retransmit_timeout,
            session_keepalive_interval: s.keepalive_interval,
            session_peer_timeout: s.peer_timeout,
            session_record_max_size: s.record_max_size,
            session_stream_send_buffer_size: s.stream_send_buffer_size,
            session_stream_receive_buffer_size: s.stream_receive_buffer_size,
            session_accepted_record_window: s.accepted_record_window,
            session_pending_ack_range_limit: s.pending_ack_range_limit,
        }
    }
}

/// synchronous driver for peer binding, handshake, and encrypted streams
pub struct QlFsm {
    config: QlFsmConfig,
    identity: QlIdentity,
    state: QlFsmState,
    events: VecDeque<Event>,
}

impl QlFsm {
    /// creates a new `QlFsm`
    pub fn new(config: QlFsmConfig, identity: QlIdentity, now: FsmTime) -> Self {
        Self {
            config,
            identity,
            state: QlFsmState {
                replay_cache: ReplayCache::default(),
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

    /// starts an outbound xx handshake using the supplied pairing token
    pub fn connect_xx(&mut self, now: FsmTime, token: PairingToken, crypto: &impl QlCrypto) {
        self.state.now = now;
        fsm::handle_connect_xx(self, token, crypto);
    }

    /// starts an IK handshake with the currently bound peer
    pub fn connect_ik(&mut self, now: FsmTime, crypto: &impl QlCrypto) -> Result<(), NoPeerError> {
        self.state.now = now;
        fsm::handle_connect_ik(self, crypto)
    }

    /// starts a KK handshake with the currently bound peer
    pub fn connect_kk(&mut self, now: FsmTime, crypto: &impl QlCrypto) -> Result<(), NoPeerError> {
        self.state.now = now;
        fsm::handle_connect_kk(self, crypto)
    }

    /// handles one inbound wire message
    pub fn receive(
        &mut self,
        now: FsmTime,
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
    pub fn on_timer(&mut self, now: FsmTime) {
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
        now: FsmTime,
        crypto: &impl QlCrypto,
    ) -> Option<OutboundWrite> {
        self.state.now = now;
        fsm::take_next_write(self, crypto)
    }

    /// completes a `SessionWriteId` from `take_next_write` with the transport outcome
    ///
    /// call this at most once for each returned `SessionWriteId`
    pub fn complete_write(&mut self, now: FsmTime, write_id: WriteId, success: bool) {
        self.state.now = now;
        fsm::complete_write(self, write_id, success);
    }

    /// closes the current encrypted session locally
    ///
    /// This transition is abortive and best-effort. It ends normal session use immediately and
    /// may emit one final outbound close record, but it does not wait for the peer to acknowledge
    /// that close.
    pub fn close_session(&mut self, code: SessionCloseCode) {
        fsm::close_session(self, code);
    }

    /// opens a new outgoing stream
    pub fn open_stream(&mut self, route_id: RouteId) -> Result<StreamOps<'_>, NoSessionError> {
        fsm::open_stream(self, route_id)
    }

    /// returns a facade for an open stream
    pub fn stream(&mut self, stream_id: StreamId) -> Result<StreamOps<'_>, StreamError> {
        fsm::stream(self, stream_id)
    }

    /// queues a ping on the active session
    pub fn queue_ping(&mut self) -> Result<(), NoSessionError> {
        fsm::queue_ping(self)
    }
}
