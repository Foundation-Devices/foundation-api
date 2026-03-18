//! sync finite state machine for quantum link protocol
//!
//! a caller drives `QlFsm` inside its own event loop
//!
//! inputs to that loop usually include
//! - app actions like `bind_peer`, `pair`, `connect`, `open_stream`, or `write_stream`
//! - inbound transport bytes passed to `receive`
//! - a deadline expiring, handled by calling `on_timer`
//! - transport write results passed to `confirm_session_write` or `reject_session_write`
//!
//! outputs from `QlFsm` are
//! - outbound records from `take_next_write`
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
    CloseCode, CloseTarget, MlDsaPublicKey, MlKemPublicKey, QlCrypto, QlIdentity, QlRecord,
    SessionCloseBody, SessionSeq, StreamClose, StreamId, XID,
};

use crate::{
    replay_cache::ReplayCache,
    session::SessionFsm,
    state::{PeerRecord, QlFsmState},
};

/// time input for `QlFsm`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsmTime {
    /// monotonic time used for local deadlines
    pub instant: Instant,
    /// wall-clock unix time used for expiration checks
    pub unix_secs: u64,
}

/// bound remote peer identity and public keys
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// peer xid
    pub xid: XID,
    /// peer signing public key
    pub signing_key: MlDsaPublicKey,
    /// peer encapsulation public key
    pub encapsulation_key: MlKemPublicKey,
}

/// connection state for the bound peer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStatus {
    /// no active encrypted session
    Disconnected,
    /// we are driving the handshake
    Initiator,
    /// the peer is driving the handshake
    Responder,
    /// the encrypted session is up
    Connected,
}

/// peer-level events emitted by `QlFsm`
#[derive(Debug, Clone)]
pub enum QlFsmEvent {
    /// a peer was bound or replaced
    NewPeer(Peer),
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
    /// the peer finished writing this stream
    Finished(StreamId),
    /// a stream was closed
    Closed(StreamClose),
    /// local writes on this stream are closed
    WritableClosed(StreamId),
    /// the peer requested unpairing
    Unpaired,
    /// the encrypted session was closed
    SessionClosed(SessionCloseBody),
}

/// handle for a session write returned by `QlFsm::take_next_write`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionWriteId(
    /// session sequence number for this write
    pub SessionSeq,
);

/// outbound record produced by `QlFsm`
#[derive(Debug, Clone, PartialEq)]
pub struct OutboundWrite {
    /// record to hand to the transport
    pub record: QlRecord,
    /// write handle that must be confirmed or rejected
    pub session_write_id: Option<SessionWriteId>,
}

/// timing and buffering knobs for `QlFsm`
#[derive(Debug, Clone, Copy)]
pub struct QlFsmConfig {
    /// overall time limit for one handshake attempt
    pub handshake_timeout: Duration,
    /// delay before retrying the current handshake message
    pub handshake_retry_interval: Duration,
    /// maximum retries for each handshake step
    pub max_handshake_retries: u8,
    /// how far into the future control messages remain valid
    pub control_expiration: Duration,
    /// delay before sending a pure ack
    pub session_ack_delay: Duration,
    /// how long to wait before resending unacked session data
    pub session_retransmit_timeout: Duration,
    /// idle delay before sending a keepalive ping
    pub session_keepalive_interval: Duration,
    /// how long to wait before declaring the peer dead
    pub session_peer_timeout: Duration,
    /// maximum bytes per outbound stream chunk
    pub session_stream_chunk_size: usize,
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
            session_stream_chunk_size: 16 * 1024,
        }
    }
}

/// synchronous driver for pairing, handshake, and encrypted streams
pub struct QlFsm {
    /// active configuration
    pub config: QlFsmConfig,
    /// local identity and private keys
    pub identity: QlIdentity,
    pub(crate) peer: Option<PeerRecord>,
    pub(crate) session: SessionFsm,
    pub(crate) state: QlFsmState,
}

impl QlFsm {
    /// creates a new `QlFsm`
    pub fn new(config: QlFsmConfig, identity: QlIdentity, now: FsmTime) -> Self {
        Self {
            config,
            identity,
            peer: None,
            session: session::SessionFsm::new(
                session::SessionFsmConfig {
                    local_namespace: session::StreamNamespace::Low,
                    stream_chunk_size: config.session_stream_chunk_size,
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

    /// binds or replaces the remote peer
    pub fn bind_peer(&mut self, peer: Peer) {
        implementation::handle_bind_peer(self, peer);
    }

    /// queues a pair request for the bound peer
    pub fn pair(&mut self, now: FsmTime, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
        self.state.now = now;
        implementation::handle_pair_local(self, crypto)
    }

    /// starts or resumes the encrypted session handshake
    pub fn connect(&mut self, now: FsmTime, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
        self.state.now = now;
        implementation::handle_connect(self, crypto)
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
    pub fn kill_session(&mut self, code: CloseCode) {
        implementation::kill_session(self, code);
    }

    /// returns the next peer-level event
    pub fn take_next_event(&mut self) -> Option<QlFsmEvent> {
        implementation::take_next_event(self)
    }

    /// opens a new outgoing stream
    pub fn open_stream(&mut self) -> Result<StreamId, QlFsmError> {
        implementation::open_stream(self)
    }

    /// queues bytes for an open stream
    pub fn write_stream(&mut self, stream_id: StreamId, bytes: Vec<u8>) -> Result<(), QlFsmError> {
        implementation::write_stream(self, stream_id, bytes)
    }

    /// reads queued bytes from a stream into `out`
    pub fn read_stream(
        &mut self,
        stream_id: StreamId,
        out: &mut [u8],
    ) -> Result<usize, QlFsmError> {
        implementation::read_stream(self, stream_id, out)
    }

    /// returns how many bytes can be read from a stream
    pub fn stream_available_bytes(&self, stream_id: StreamId) -> Result<usize, QlFsmError> {
        implementation::stream_available_bytes(self, stream_id)
    }

    /// marks the local write side as finished
    pub fn finish_stream(&mut self, stream_id: StreamId) -> Result<(), QlFsmError> {
        implementation::finish_stream(self, stream_id)
    }

    /// closes part or all of a stream
    pub fn close_stream(
        &mut self,
        stream_id: StreamId,
        target: CloseTarget,
        code: CloseCode,
        payload: Vec<u8>,
    ) -> Result<(), QlFsmError> {
        implementation::close_stream(self, stream_id, target, code, payload)
    }

    /// queues a ping on the active session
    pub fn queue_ping(&mut self) -> Result<(), QlFsmError> {
        implementation::queue_ping(self)
    }

    /// queues an unpair request on the active session
    pub fn queue_unpair(&mut self) -> Result<(), QlFsmError> {
        implementation::queue_unpair(self)
    }

    /// returns the next session or stream event
    pub fn take_next_session_event(&mut self) -> Option<QlSessionEvent> {
        implementation::take_next_session_event(self)
    }
}
