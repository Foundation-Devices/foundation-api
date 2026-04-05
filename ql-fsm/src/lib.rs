//! sync finite state machine for quantum link protocol
//!
//! a caller drives `QlFsm` inside its own event loop
//!
//! inputs to that loop usually include
//! - app actions like `bind_peer`, `connect_ik`, `connect_kk`, `open_stream`, or `write_stream`
//! - inbound transport bytes passed to `receive`
//! - a deadline expiring, handled by calling `on_timer`
//! - transport write results passed to `confirm_session_write` or `reject_session_write`
//!
//! outputs from `QlFsm` are
//! - outbound session and handshake records from `take_next_write`
//! - peer events from `take_next_event`
//! - session events from `take_next_session_event`
//!
//! call `next_deadline` after handling current inputs and draining current outputs
//! use it to decide how long the outer loop can wait before `on_timer` must run
//! another input may arrive before that deadline, which is fine

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
    CloseTarget, PeerBundle, QlCrypto, QlIdentity, SessionClose, SessionCloseCode, StreamClose,
    StreamCloseCode, StreamId, XID,
};
pub use session::stream_rx::StreamReadIter;

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

/// peer-level events emitted by `QlFsm`
#[derive(Debug, Clone)]
pub enum QlFsmEvent {
    /// a peer was bound or replaced
    NewPeer(PeerBundle),
    /// the bound peer was cleared
    ClearPeer,
    /// the peer changed connection state
    PeerStatusChanged {
        /// peer that changed state
        peer: XID,
        /// new connection state
        status: PeerStatus,
    },
}

/// session and stream events emitted by `QlFsm`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QlSessionEvent {
    /// a stream was opened
    Opened(StreamId),
    /// a stream has bytes ready to read
    Readable(StreamId),
    /// a stream has room for more local writes
    Writable(StreamId),
    /// the peer finished writing this stream
    Finished(StreamId),
    /// a stream was closed
    Closed(StreamClose),
    /// local writes on this stream are closed
    WritableClosed(StreamId),
    /// the peer requested unpairing
    Unpaired,
    /// the encrypted session was closed
    SessionClosed(SessionClose),
}

/// handle for a session write returned by `QlFsm::take_next_write`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionWriteId(pub(crate) u64);

/// outbound record produced by `QlFsm`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundWrite {
    /// wire bytes to hand to the transport
    pub record: Vec<u8>,
    /// write handle that must be confirmed or rejected
    pub session_write_id: Option<SessionWriteId>,
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
}

impl Default for QlFsmConfig {
    fn default() -> Self {
        let s = session::SessionFsmConfig::default();
        Self {
            handshake_timeout: Duration::from_secs(5),
            session_record_ack_delay: s.ack_delay,
            session_record_retransmit_timeout: s.retransmit_timeout,
            session_keepalive_interval: s.keepalive_interval,
            session_peer_timeout: s.peer_timeout,
            session_record_max_size: s.record_max_size,
            session_stream_send_buffer_size: s.stream_send_buffer_size,
            session_stream_receive_buffer_size: s.stream_receive_buffer_size,
        }
    }
}

/// synchronous driver for peer binding, handshake, and encrypted streams
pub struct QlFsm {
    /// active configuration
    pub config: QlFsmConfig,
    /// local identity and private keys
    pub identity: QlIdentity,
    pub(crate) state: QlFsmState,
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
                handshake: None,
                link: LinkState::Idle,
                events: Default::default(),
                session_events: Default::default(),
                now,
            },
        }
    }

    /// binds or replaces the remote peer
    pub fn bind_peer(&mut self, peer: PeerBundle) {
        implementation::handle_bind_peer(self, peer);
    }

    /// starts or replaces an IK handshake with the currently bound peer
    pub fn connect_ik(&mut self, now: FsmTime, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
        self.state.now = now;
        implementation::handle_connect_ik(self, crypto)
    }

    /// starts or replaces a KK handshake with the currently bound peer
    pub fn connect_kk(&mut self, now: FsmTime, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
        self.state.now = now;
        implementation::handle_connect_kk(self, crypto)
    }

    /// handles one inbound wire message
    pub fn receive(
        &mut self,
        now: FsmTime,
        bytes: Vec<u8>,
        crypto: &impl QlCrypto,
    ) -> Result<(), QlFsmError> {
        self.state.now = now;
        implementation::receive(self, bytes, crypto)
    }

    /// advances time-based state
    pub fn on_timer(&mut self, now: FsmTime) {
        self.state.now = now;
        implementation::on_timer(self);
    }

    /// returns the next timer deadline, if any
    pub fn next_deadline(&self) -> Option<Instant> {
        implementation::next_deadline(self)
    }

    /// returns the next outbound record
    ///
    /// if `session_write_id` is `Some`, call exactly one of
    /// `confirm_session_write` or `reject_session_write`
    ///
    /// if it is `None`, the record is fire-and-forget
    pub fn take_next_write(
        &mut self,
        now: FsmTime,
        crypto: &impl QlCrypto,
    ) -> Option<OutboundWrite> {
        self.state.now = now;
        implementation::take_next_write(self, crypto)
    }

    /// marks a `SessionWriteId` from `take_next_write` as handed to the transport
    ///
    /// call this at most once for each returned `SessionWriteId`
    pub fn confirm_session_write(&mut self, now: FsmTime, write_id: SessionWriteId) {
        self.state.now = now;
        implementation::confirm_session_write(self, write_id);
    }

    /// reports that a `SessionWriteId` from `take_next_write` was not accepted
    ///
    /// call this at most once for each returned `SessionWriteId`
    pub fn reject_session_write(&mut self, write_id: SessionWriteId) {
        implementation::reject_session_write(self, write_id);
    }

    /// closes the current encrypted session locally
    pub fn kill_session(&mut self, code: SessionCloseCode) {
        implementation::kill_session(self, code);
    }

    /// returns the next peer-level event
    pub fn take_next_event(&mut self) -> Option<QlFsmEvent> {
        self.state.events.pop_front()
    }

    /// opens a new outgoing stream
    pub fn open_stream(&mut self) -> Result<StreamId, QlFsmError> {
        implementation::open_stream(self)
    }

    /// queues bytes for an open stream and returns the accepted count
    pub fn write_stream(&mut self, stream_id: StreamId, bytes: &[u8]) -> Result<usize, QlFsmError> {
        implementation::write_stream(self, stream_id, bytes)
    }

    /// returns the readable stream bytes as borrowed chunks without consuming them
    pub fn stream_read(&self, stream_id: StreamId) -> Option<StreamReadIter<'_>> {
        implementation::stream_read(self, stream_id)
    }

    /// marks previously read bytes as consumed
    pub fn stream_read_commit(
        &mut self,
        stream_id: StreamId,
        len: usize,
    ) -> Result<(), QlFsmError> {
        implementation::stream_read_commit(self, stream_id, len)
    }

    /// returns how many bytes can be read from a stream
    pub fn stream_available_bytes(&self, stream_id: StreamId) -> Option<usize> {
        implementation::stream_available_bytes(self, stream_id)
    }

    /// marks the local write side as finished
    pub fn finish_stream(&mut self, stream_id: StreamId) -> Result<(), QlFsmError> {
        implementation::finish_stream(self, stream_id)
    }

    /// closes the origin lane, return lane, or both lanes of a stream
    pub fn close_stream(
        &mut self,
        stream_id: StreamId,
        target: CloseTarget,
        code: StreamCloseCode,
    ) -> Result<(), QlFsmError> {
        implementation::close_stream(self, stream_id, target, code)
    }

    /// queues a ping on the active session
    pub fn queue_ping(&mut self) -> Result<(), QlFsmError> {
        implementation::queue_ping(self)
    }

    /// returns the next session or stream event
    pub fn take_next_session_event(&mut self) -> Option<QlSessionEvent> {
        self.state.session_events.pop_front()
    }
}
