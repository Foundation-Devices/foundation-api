use std::time::Instant;

use bytes::Bytes;
use indexmap::IndexMap;
use ql_common::StreamId;
use ql_wire::{RecordSeq, ResetTarget, SessionClose, StreamReset};

use super::{
    ack_tracker::AckTracker,
    remote_stream_history::RemoteStreamHistory,
    replay_window::ReplayWindow,
    stream_rx::StreamRx,
    stream_tx::{StreamTx, StreamTxRange},
    tracked::{LossRecovery, TrackedFrame, TrackedRecord},
};

pub struct SessionState {
    pub last_activity_at: Instant,
    pub last_inbound_at: Instant,
    pub phase: SessionPhase,
    pub next_stream_ordinal: u32,
    pub next_record_seq: RecordSeq,
    pub next_write_id: u64,
    pub tracked_records: IndexMap<u64, TrackedRecord>,
    pub loss_recovery: LossRecovery,
    pub replay_window: ReplayWindow,
    pub ack_tracker: AckTracker,
    pub pending_ping: bool,
    pub streams: IndexMap<StreamId, StreamState>,
    pub next_stream_index: usize,
    pub remote_stream_history: RemoteStreamHistory,
}

impl SessionState {
    pub fn restore_tracked_record(&mut self, now: Instant, record: &TrackedRecord) {
        if let Some(ack) = &record.ack {
            self.ack_tracker.restore_acked_ranges(ack, now);
        }
        for frame in &record.frames {
            self.requeue_tracked_frame(frame);
        }
    }

    fn requeue_tracked_frame(&mut self, frame: &TrackedFrame) {
        match frame {
            TrackedFrame::StreamReset(reset) => {
                if let Some(stream) = self.streams.get_mut(&reset.stream_id) {
                    stream.pending_reset = Some(reset.clone());
                }
            }
            TrackedFrame::StreamData(frame) => {
                let Some(stream) = self.streams.get_mut(&frame.stream_id) else {
                    return;
                };
                if matches!(stream.outbound_state, OutboundState::Closed) {
                    return;
                }
                stream.tx.retransmit(StreamTxRange {
                    offset: frame.offset,
                    len: frame.len,
                    fin: frame.fin,
                });
                if frame.fin && matches!(stream.outbound_state, OutboundState::Finished) {
                    stream.outbound_state = OutboundState::FinQueued;
                }
            }
            TrackedFrame::StreamWindow(stream_id, maximum_offset) => {
                if let Some(stream) = self.streams.get_mut(stream_id) {
                    stream.pending_window |= stream.recv_limit() >= *maximum_offset;
                }
            }
            TrackedFrame::Ping => self.pending_ping = true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionPhase {
    Open,
    Terminating(TerminalFrame),
    Closed,
}

impl SessionPhase {
    pub fn is_open(&self) -> bool {
        self == &Self::Open
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalFrame {
    Close(SessionClose),
    Unpair,
}

#[derive(Debug)]
pub struct StreamState {
    pub role: StreamRole,
    pub header: Option<Bytes>,
    pub rx: StreamRx,
    pub tx: StreamTx,
    pub pending_reset: Option<StreamReset>,
    pub peer_max_offset: u64,
    pub outbound_state: OutboundState,
    pub inbound_state: InboundState,
    pub advertised_max_offset: u64,
    pub pending_window: bool,
}

impl StreamState {
    pub fn new(
        role: StreamRole,
        header: Option<Bytes>,
        receive_buffer_size: u32,
        initial_peer_stream_receive_window: u32,
    ) -> Self {
        let receive_buffer_size = receive_buffer_size as usize;
        Self {
            role,
            header,
            tx: StreamTx::new(),
            pending_reset: None,
            peer_max_offset: u64::from(initial_peer_stream_receive_window),
            outbound_state: OutboundState::Open,
            inbound_state: InboundState::Open,
            rx: StreamRx::new(receive_buffer_size),
            advertised_max_offset: receive_buffer_size as u64,
            pending_window: false,
        }
    }

    pub fn is_writable(&self) -> bool {
        matches!(self.outbound_state, OutboundState::Open)
    }

    pub fn send_capacity(&self, send_buffer_size: usize) -> usize {
        send_buffer_size.saturating_sub(self.tx.buffered_len())
    }

    pub fn readable_bytes(&self) -> usize {
        self.rx.readable_len()
    }

    pub fn recv_limit(&self) -> u64 {
        self.rx
            .start_offset()
            .saturating_add(self.rx.max_buffered() as u64)
    }

    pub fn reset_recv(&mut self) {
        self.rx = StreamRx::with_start_offset(self.rx.start_offset(), self.rx.max_buffered());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRole {
    Initiator,
    Responder,
}

impl StreamRole {
    pub fn outbound_target(self) -> ResetTarget {
        match self {
            Self::Initiator => ResetTarget::Origin,
            Self::Responder => ResetTarget::Return,
        }
    }

    pub fn inbound_target(self) -> ResetTarget {
        match self {
            Self::Initiator => ResetTarget::Return,
            Self::Responder => ResetTarget::Origin,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundState {
    Open,
    FinQueued,
    Finished,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundState {
    Open,
    Finished,
    Reset(StreamReset),
    Discarding,
}
