use std::{collections::BTreeSet, time::Instant};

use indexmap::IndexMap;
use ql_wire::{
    CloseTarget, RecordAck, RecordAckRange, RecordSeq, SessionClose, StreamClose, StreamId, XID,
};

use super::{
    stream_rx::StreamRx, stream_tx::StreamTx, SessionState, SESSION_RECORD_TRACKED_WINDOW,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamParity {
    Even,
    Odd,
}

impl StreamParity {
    pub fn for_local(local: XID, peer: XID) -> Self {
        match local.0.cmp(&peer.0) {
            std::cmp::Ordering::Less | std::cmp::Ordering::Equal => Self::Even,
            std::cmp::Ordering::Greater => Self::Odd,
        }
    }

    pub const fn first_stream_id(self) -> u32 {
        match self {
            Self::Even => 0,
            Self::Odd => 1,
        }
    }

    pub const fn matches(self, stream_id: StreamId) -> bool {
        match self {
            Self::Even => stream_id.0 % 2 == 0,
            Self::Odd => stream_id.0 % 2 == 1,
        }
    }

    pub const fn remote(self) -> Self {
        match self {
            Self::Even => Self::Odd,
            Self::Odd => Self::Even,
        }
    }

    pub fn make_stream_id(self, ordinal: u32) -> StreamId {
        StreamId(
            self.first_stream_id()
                .saturating_add(ordinal.saturating_mul(2)),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRole {
    Initiator,
    Responder,
}

impl StreamRole {
    pub fn outbound_target(self) -> CloseTarget {
        match self {
            Self::Initiator => CloseTarget::Request,
            Self::Responder => CloseTarget::Response,
        }
    }

    pub fn inbound_target(self) -> CloseTarget {
        match self {
            Self::Initiator => CloseTarget::Response,
            Self::Responder => CloseTarget::Request,
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
    Closed(StreamClose),
    Discarding,
}

#[derive(Debug)]
pub struct StreamState {
    pub role: StreamRole,
    pub rx: StreamRx,
    pub tx: StreamTx,
    pub pending_close: Option<StreamClose>,
    pub peer_max_offset: u64,
    pub outbound_state: OutboundState,
    pub inbound_state: InboundState,
    pub advertised_max_offset: u64,
    pub pending_window: bool,
}

impl StreamState {
    pub fn new(role: StreamRole, receive_buffer_size: usize) -> Self {
        Self {
            role,
            tx: StreamTx::new(),
            pending_close: None,
            peer_max_offset: receive_buffer_size as u64,
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

    pub fn buffered_send_bytes(&self) -> usize {
        self.tx.buffered_len()
    }

    pub fn send_capacity(&self, send_buffer_size: usize) -> usize {
        send_buffer_size.saturating_sub(self.buffered_send_bytes())
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

#[derive(Debug, Clone)]
pub enum ReliableFrame {
    StreamData(StreamDataManifest),
    StreamClose(StreamClose),
    Close(SessionClose),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamDataManifest {
    pub stream_id: StreamId,
    pub offset: u64,
    pub len: usize,
    pub fin: bool,
}

#[derive(Debug, Clone)]
pub struct OutboundRecord {
    pub seq: RecordSeq,
    pub reliable: Vec<ReliableFrame>,
    pub ack_included: bool,
    pub ping_included: bool,
    pub window_updates: Vec<(StreamId, u64)>,
    pub sent_at: Option<Instant>,
}

#[derive(Debug, Clone, Default)]
pub struct PendingSessionControl {
    pub ping: bool,
    pub close: Option<SessionClose>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckState {
    Idle,
    Delayed { due_at: Instant },
    Immediate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveInsertOutcome {
    New { out_of_order: bool },
    Duplicate,
}

#[derive(Debug, Default)]
pub struct ReceivedRecords {
    seen: BTreeSet<u64>,
    largest: Option<u64>,
}

impl ReceivedRecords {
    pub fn insert(&mut self, seq: RecordSeq) -> ReceiveInsertOutcome {
        if self.seen.contains(&seq.0) {
            return ReceiveInsertOutcome::Duplicate;
        }

        if self
            .largest
            .is_some_and(|largest| largest.saturating_sub(seq.0) > SESSION_RECORD_TRACKED_WINDOW)
        {
            return ReceiveInsertOutcome::Duplicate;
        }

        let out_of_order = self
            .largest
            .is_some_and(|largest| seq.0 != largest.saturating_add(1));
        self.seen.insert(seq.0);
        self.largest = Some(self.largest.map_or(seq.0, |largest| largest.max(seq.0)));
        self.prune();
        ReceiveInsertOutcome::New { out_of_order }
    }

    pub fn ack(&self) -> Option<RecordAck> {
        if self.seen.is_empty() {
            return None;
        }

        let mut ranges = Vec::new();
        let mut iter = self.seen.iter().copied();
        let first = iter.next()?;
        let mut start = first;
        let mut end = first.saturating_add(1);

        for seq in iter {
            if seq == end {
                end = end.saturating_add(1);
                continue;
            }

            ranges.push(RecordAckRange { start, end });
            start = seq;
            end = seq.saturating_add(1);
        }

        ranges.push(RecordAckRange { start, end });
        Some(RecordAck { ranges })
    }

    fn prune(&mut self) {
        let Some(largest) = self.largest else {
            return;
        };
        let keep_from = largest.saturating_sub(SESSION_RECORD_TRACKED_WINDOW);
        self.seen.retain(|seq| *seq >= keep_from);
    }
}

pub struct SessionFsmState {
    pub now: Instant,
    pub last_activity_at: Instant,
    pub last_inbound_at: Instant,
    pub session_state: SessionState,
    pub next_stream_ordinal: u32,
    pub next_record_seq: RecordSeq,
    pub next_write_id: u64,
    pub outbound_records: IndexMap<u64, OutboundRecord>,
    pub received_records: ReceivedRecords,
    pub ack_state: AckState,
    pub pending_control: PendingSessionControl,
    pub streams: IndexMap<StreamId, StreamState>,
    pub next_stream_index: usize,
}
