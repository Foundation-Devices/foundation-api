pub(crate) mod internal;
pub(crate) mod ring;
pub(crate) mod state;

#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};

use ql_wire::{
    CloseCode, CloseTarget, SessionCloseBody, SessionEnvelope, StreamCloseFrame, StreamId, XID,
};

use self::state::SessionFsmState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamNamespace {
    Low,
    High,
}

impl StreamNamespace {
    const BIT: u32 = 1 << 31;

    pub fn for_local(local: XID, peer: XID) -> Self {
        match local.0.cmp(&peer.0) {
            std::cmp::Ordering::Less | std::cmp::Ordering::Equal => Self::Low,
            std::cmp::Ordering::Greater => Self::High,
        }
    }

    pub fn bit(self) -> u32 {
        match self {
            Self::Low => 0,
            Self::High => Self::BIT,
        }
    }

    pub fn matches(self, stream_id: StreamId) -> bool {
        (stream_id.0 & Self::BIT) == self.bit()
    }

    pub fn remote(self) -> Self {
        match self {
            Self::Low => Self::High,
            Self::High => Self::Low,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SessionFsmConfig {
    pub local_namespace: StreamNamespace,
    pub ack_delay: Duration,
    pub retransmit_timeout: Duration,
    pub keepalive_interval: Duration,
    pub peer_timeout: Duration,
}

impl Default for SessionFsmConfig {
    fn default() -> Self {
        Self {
            local_namespace: StreamNamespace::Low,
            ack_delay: Duration::from_millis(5),
            retransmit_timeout: Duration::from_millis(150),
            keepalive_interval: Duration::from_secs(10),
            peer_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    Opened(StreamId),
    Readable(StreamId),
    WritableClosed(StreamId),
    Unpaired,
    SessionClosed(SessionCloseBody),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamIncoming {
    Data(Vec<u8>),
    Finished,
    Closed(StreamCloseFrame),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    #[error("missing stream")]
    MissingStream,
    #[error("stream is not writable")]
    NotWritable,
    #[error("session is closed")]
    SessionClosed,
}

pub struct SessionFsm {
    config: SessionFsmConfig,
    state: SessionFsmState,
}

impl SessionFsm {
    pub fn new(config: SessionFsmConfig, now: Instant) -> Self {
        Self::new_inner(config, now)
    }

    pub fn open_stream(&mut self) -> Result<StreamId, StreamError> {
        self.open_stream_inner()
    }

    pub fn write_stream(&mut self, stream_id: StreamId, bytes: Vec<u8>) -> Result<(), StreamError> {
        self.write_stream_inner(stream_id, bytes)
    }

    pub fn finish_stream(&mut self, stream_id: StreamId) -> Result<(), StreamError> {
        self.finish_stream_inner(stream_id)
    }

    pub fn close_stream(
        &mut self,
        stream_id: StreamId,
        target: CloseTarget,
        code: CloseCode,
        payload: Vec<u8>,
    ) -> Result<(), StreamError> {
        self.close_stream_inner(stream_id, target, code, payload)
    }

    pub fn queue_ping(&mut self) -> Result<(), StreamError> {
        self.queue_ping_inner()
    }

    pub fn queue_unpair(&mut self) -> Result<(), StreamError> {
        self.queue_unpair_inner()
    }

    pub fn close_session(&mut self, code: CloseCode) {
        self.close_session_inner(code);
    }

    pub fn receive(&mut self, now: Instant, envelope: SessionEnvelope) {
        self.state.now = now;
        self.receive_inner(envelope);
    }

    pub fn next_outbound(&mut self, now: Instant) -> Option<SessionEnvelope> {
        self.state.now = now;
        self.next_outbound_inner()
    }

    pub fn on_timer(&mut self, now: Instant) {
        self.state.now = now;
        self.on_timer_inner();
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.next_deadline_inner()
    }

    pub fn take_next_event(&mut self) -> Option<SessionEvent> {
        self.take_next_event_inner()
    }

    pub fn take_next_inbound(&mut self, stream_id: StreamId) -> Option<StreamIncoming> {
        self.take_next_inbound_inner(stream_id)
    }

    pub fn session_state(&self) -> SessionState {
        self.session_state_inner()
    }
}
