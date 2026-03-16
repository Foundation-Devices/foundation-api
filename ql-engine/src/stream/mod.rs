use std::time::{Duration, Instant};

use thiserror::Error;

use crate::{
    wire::{
        stream::{BodyChunk, StreamBody, StreamFrameClose},
        StreamSeq,
    },
    StreamId,
};

pub(crate) mod internal;
pub(crate) mod ring;

#[cfg(test)]
mod tests;

pub const STREAM_WINDOW_CAPACITY: usize = 8;
pub const STREAM_WINDOW_SIZE: u32 = STREAM_WINDOW_CAPACITY as u32;
pub const STREAM_ACK_EAGER_THRESHOLD: u32 = STREAM_WINDOW_SIZE / 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamNamespace {
    Low,
    High,
}

impl StreamNamespace {
    const BIT: u32 = 1 << 31;

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
pub struct StreamFsmConfig {
    pub local_namespace: StreamNamespace,
    pub ack_delay: Duration,
    pub ack_timeout: Duration,
    pub fast_retransmit_threshold: u8,
    pub retry_limit: u8,
}

impl Default for StreamFsmConfig {
    fn default() -> Self {
        Self {
            local_namespace: StreamNamespace::Low,
            ack_delay: Duration::from_millis(5),
            ack_timeout: Duration::from_millis(150),
            fast_retransmit_threshold: 2,
            retry_limit: 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutboundCompletion {
    Ack {
        stream_id: StreamId,
    },
    Frame {
        stream_id: StreamId,
        tx_seq: StreamSeq,
        issue_id: u64,
    },
}

impl OutboundCompletion {
    pub fn stream_id(self) -> StreamId {
        match self {
            Self::Ack { stream_id } | Self::Frame { stream_id, .. } => stream_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    pub body: StreamBody,
    pub completion: OutboundCompletion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamCloseKind {
    Detached,
    Acked,
    Remote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamLocalRole {
    Initiator,
    Responder,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCloseEvent {
    pub kind: StreamCloseKind,
    pub role: StreamLocalRole,
    pub frame: StreamFrameClose,
}

pub trait StreamEventSink {
    fn opened(
        &mut self,
        stream_id: StreamId,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
    );

    fn inbound_data(&mut self, stream_id: StreamId, bytes: Vec<u8>);

    fn inbound_finished(&mut self, stream_id: StreamId);

    fn inbound_failed(&mut self, stream_id: StreamId, error: StreamError);

    fn close(&mut self, event: StreamCloseEvent);

    fn outbound_closed(&mut self, stream_id: StreamId);

    fn outbound_failed(&mut self, stream_id: StreamId, error: StreamError);

    fn reaped(&mut self, stream_id: StreamId);
}

impl StreamEventSink for () {
    fn opened(
        &mut self,
        _stream_id: StreamId,
        _request_head: Vec<u8>,
        _request_prefix: Option<BodyChunk>,
    ) {
    }

    fn inbound_data(&mut self, _stream_id: StreamId, _bytes: Vec<u8>) {}

    fn inbound_finished(&mut self, _stream_id: StreamId) {}

    fn inbound_failed(&mut self, _stream_id: StreamId, _error: StreamError) {}

    fn close(&mut self, _event: StreamCloseEvent) {}

    fn outbound_closed(&mut self, _stream_id: StreamId) {}

    fn outbound_failed(&mut self, _stream_id: StreamId, _error: StreamError) {}

    fn reaped(&mut self, _stream_id: StreamId) {}
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StreamError {
    #[error("missing stream")]
    MissingStream,
    #[error("stream is not writable")]
    NotWritable,
    #[error("send failed")]
    SendFailed,
    #[error("timeout")]
    Timeout,
    #[error("cancelled")]
    Cancelled,
    #[error("stream protocol error")]
    StreamProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WriteError {
    #[error("send failed")]
    SendFailed,
}

pub struct StreamFsm {
    config: StreamFsmConfig,
    pub(crate) streams: internal::StreamStore,
    next_stream_id: u32,
    next_issue_id: u64,
}

impl StreamFsm {
    pub fn new(config: StreamFsmConfig) -> Self {
        internal::new(config)
    }

    pub fn open_stream(
        &mut self,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
    ) -> StreamId {
        internal::open_stream(self, request_head, request_prefix)
    }

    pub fn write_stream(&mut self, stream_id: StreamId, bytes: Vec<u8>) -> Result<(), StreamError> {
        internal::write_stream(self, stream_id, bytes)
    }

    pub fn finish_stream(&mut self, stream_id: StreamId) -> Result<(), StreamError> {
        internal::finish_stream(self, stream_id)
    }

    pub fn close_stream(
        &mut self,
        stream_id: StreamId,
        target: crate::wire::stream::CloseTarget,
        code: crate::wire::stream::CloseCode,
        payload: Vec<u8>,
    ) -> Result<(), StreamError> {
        internal::close_stream(self, stream_id, target, code, payload)
    }

    pub fn receive(&mut self, now: Instant, body: StreamBody, events: &mut impl StreamEventSink) {
        internal::receive(self, now, body, events);
    }

    pub fn next_outbound(&mut self, now: Instant, valid_until: u64) -> Option<Outbound> {
        internal::next_outbound(self, now, valid_until)
    }

    pub fn complete_outbound(
        &mut self,
        now: Instant,
        completion: OutboundCompletion,
        result: Result<(), WriteError>,
        events: &mut impl StreamEventSink,
    ) {
        internal::complete_outbound(self, now, completion, result, events);
    }

    pub fn on_timer(&mut self, now: Instant, events: &mut impl StreamEventSink) {
        internal::on_timer(self, now, events);
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        internal::next_deadline(self)
    }

    pub fn abort(&mut self, error: StreamError, events: &mut impl StreamEventSink) {
        internal::abort(self, error, events);
    }

    pub fn set_local_namespace(&mut self, local_namespace: StreamNamespace) {
        self.config.local_namespace = local_namespace;
    }
}
