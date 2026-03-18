use std::{
    cell::Cell,
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, VecDeque},
    time::Instant,
};

use bc_components::{MLDSAPublicKey, MLKEMPublicKey, SymmetricKey, XID};

use super::{
    replay_cache::ReplayCache,
    stream::{AwaitingFrame, AwaitingPacket, QueuedWrite, StreamControl, StreamKey, StreamState},
    EngineConfig,
};
use crate::{
    runtime::StreamConfig,
    wire::{
        handshake::{Hello, HelloReply, ResponderSecrets},
        stream::{Direction, RejectCode, ResetCode, StreamBody, StreamFrame, StreamFrameData},
    },
    PacketId, Peer, QlError, StreamId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpenId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackedWrite {
    pub stream_id: StreamId,
    pub packet_id: PacketId,
}

#[derive(Debug, Clone)]
pub struct KeepAliveState {
    pub token: Token,
    pub pending: bool,
    pub last_activity: Option<Instant>,
}

impl Default for KeepAliveState {
    fn default() -> Self {
        Self {
            token: Token(0),
            pending: false,
            last_activity: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitiatorStage {
    WaitingHelloReply,
    SendingConfirm,
}

#[derive(Debug, Clone)]
pub enum PeerSession {
    Disconnected,
    Initiator {
        handshake_token: Token,
        hello: Hello,
        session_key: SymmetricKey,
        deadline: Instant,
        stage: InitiatorStage,
    },
    Responder {
        handshake_token: Token,
        hello: Hello,
        reply: HelloReply,
        secrets: ResponderSecrets,
        deadline: Instant,
    },
    Connected {
        session_key: SymmetricKey,
        keepalive: KeepAliveState,
    },
}

impl PeerSession {
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected { .. })
    }

    pub fn session_key(&self) -> Option<&SymmetricKey> {
        match self {
            Self::Connected { session_key, .. } => Some(session_key),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub peer: XID,
    pub signing_key: MLDSAPublicKey,
    pub encapsulation_key: MLKEMPublicKey,
    pub session: PeerSession,
}

impl PeerRecord {
    pub fn new(peer: XID, signing_key: MLDSAPublicKey, encapsulation_key: MLKEMPublicKey) -> Self {
        Self {
            peer,
            signing_key,
            encapsulation_key,
            session: PeerSession::Disconnected,
        }
    }

    pub fn snapshot(&self) -> Peer {
        Peer {
            peer: self.peer,
            signing_key: self.signing_key.clone(),
            encapsulation_key: self.encapsulation_key.clone(),
        }
    }
}

#[derive(Debug)]
pub enum EngineInput {
    BindPeer(Peer),
    Pair,
    Connect,
    Unpair,

    OpenStream {
        open_id: OpenId,
        request_head: Vec<u8>,
        config: StreamConfig,
    },
    AcceptStream {
        stream_id: StreamId,
        response_head: Vec<u8>,
    },
    RejectStream {
        stream_id: StreamId,
        code: RejectCode,
    },

    OutboundData {
        stream_id: StreamId,
        dir: Direction,
        offset: u64,
        bytes: Vec<u8>,
    },
    OutboundFinished {
        stream_id: StreamId,
        dir: Direction,
        final_offset: u64,
    },
    InboundConsumed {
        stream_id: StreamId,
        dir: Direction,
        amount: u64,
    },

    ResetOutbound {
        stream_id: StreamId,
        dir: Direction,
        code: ResetCode,
    },
    ResetInbound {
        stream_id: StreamId,
        dir: Direction,
        code: ResetCode,
    },
    PendingAcceptDropped {
        stream_id: StreamId,
    },
    ResponderDropped {
        stream_id: StreamId,
    },

    Incoming(Vec<u8>),
    WriteCompleted {
        token: Token,
        tracked: Option<TrackedWrite>,
        result: Result<(), QlError>,
    },
    TimerExpired,
}

#[derive(Debug)]
pub enum EngineOutput {
    SetTimer(Option<Instant>),
    WriteMessage {
        token: Token,
        tracked: Option<TrackedWrite>,
        bytes: Vec<u8>,
    },

    PeerStatusChanged {
        peer: XID,
        session: PeerSession,
    },
    PersistPeer(Peer),
    ClearPeer,

    OpenStarted {
        open_id: OpenId,
        stream_id: StreamId,
    },
    OpenAccepted {
        open_id: OpenId,
        stream_id: StreamId,
        response_head: Vec<u8>,
    },
    OpenFailed {
        open_id: OpenId,
        stream_id: StreamId,
        error: QlError,
    },

    InboundStreamOpened {
        stream_id: StreamId,
        request_head: Vec<u8>,
    },
    InboundData {
        stream_id: StreamId,
        dir: Direction,
        bytes: Vec<u8>,
    },
    InboundFinished {
        stream_id: StreamId,
        dir: Direction,
    },
    InboundFailed {
        stream_id: StreamId,
        dir: Direction,
        error: QlError,
    },

    NeedOutboundData {
        stream_id: StreamId,
        dir: Direction,
        offset: u64,
        max_len: usize,
    },
    ReleaseOutboundThrough {
        stream_id: StreamId,
        dir: Direction,
        recv_offset: u64,
    },
    OutboundClosed {
        stream_id: StreamId,
        dir: Direction,
    },
    OutboundFailed {
        stream_id: StreamId,
        dir: Direction,
        error: QlError,
    },

    StreamReaped {
        stream_id: StreamId,
    },
}

pub trait OutputFn: FnMut(EngineOutput) {}

impl<T> OutputFn for T where T: FnMut(EngineOutput) {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutKind {
    Outbound {
        token: Token,
    },
    Handshake {
        token: Token,
    },
    KeepAliveSend {
        token: Token,
    },
    KeepAliveTimeout {
        token: Token,
    },
    StreamOpen {
        stream_id: StreamId,
        token: Token,
    },
    StreamPacket {
        stream_id: StreamId,
        packet_id: PacketId,
        attempt: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutEntry {
    pub at: Instant,
    pub kind: TimeoutKind,
}

impl Ord for TimeoutEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.at.cmp(&other.at)
    }
}

impl PartialOrd for TimeoutEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
pub enum HelloAction {
    StartResponder,
    ResendReply {
        reply: HelloReply,
        deadline: Instant,
    },
    Ignore,
}

pub struct Engine {
    pub config: EngineConfig,
    pub state: EngineState,
    pub streams: HashMap<StreamId, StreamState>,
}

pub struct EngineState {
    pub peer: Option<PeerRecord>,
    pub replay_cache: ReplayCache,

    pub next_token: Cell<u64>,
    pub next_packet_id: Cell<u32>,
    pub next_stream_id: Cell<u64>,
    pub outbound: VecDeque<QueuedWrite>,
    pub timeouts: BinaryHeap<Reverse<TimeoutEntry>>,
    pub write_in_flight: Option<Token>,
}

impl EngineState {
    pub fn new(peer: Option<Peer>) -> Self {
        Self {
            peer: peer
                .map(|peer| PeerRecord::new(peer.peer, peer.signing_key, peer.encapsulation_key)),
            replay_cache: ReplayCache::new(),
            next_token: Cell::new(1),
            next_packet_id: Cell::new(1),
            next_stream_id: Cell::new(1),
            outbound: VecDeque::new(),
            timeouts: BinaryHeap::new(),
            write_in_flight: None,
        }
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.timeouts.peek().map(|entry| entry.0.at)
    }

    pub fn next_token(&self) -> Token {
        let token = self.next_token.get();
        self.next_token.set(token.wrapping_add(1));
        Token(token)
    }

    pub fn next_packet_id(&self) -> PacketId {
        let id = self.next_packet_id.get();
        self.next_packet_id.set(id.wrapping_add(1));
        PacketId(id)
    }

    pub fn next_stream_id(&self) -> StreamId {
        let id = self.next_stream_id.get();
        self.next_stream_id.set(id.wrapping_add(1));
        StreamId(id)
    }

    pub fn enqueue_handshake_message(
        &mut self,
        _config: &EngineConfig,
        token: Token,
        deadline: Instant,
        bytes: Vec<u8>,
    ) {
        self.outbound.push_back(QueuedWrite {
            token,
            stream_id: None,
            packet_id: None,
            track_ack: false,
            payload: super::stream::QueuedPayload::PreEncoded(bytes),
        });
        self.timeouts.push(Reverse(TimeoutEntry {
            at: deadline,
            kind: TimeoutKind::Handshake { token },
        }));
        self.timeouts.push(Reverse(TimeoutEntry {
            at: deadline,
            kind: TimeoutKind::Outbound { token },
        }));
    }

    pub fn enqueue_stream_body(
        &mut self,
        config: &EngineConfig,
        stream_id: Option<StreamId>,
        packet_id: Option<PacketId>,
        track_ack: bool,
        priority: bool,
        body: StreamBody,
    ) {
        let token = self.next_token();
        let message = QueuedWrite {
            token,
            stream_id,
            packet_id,
            track_ack,
            payload: super::stream::QueuedPayload::StreamBody(body),
        };
        if priority {
            self.outbound.push_front(message);
        } else {
            self.outbound.push_back(message);
        }
        self.timeouts.push(Reverse(TimeoutEntry {
            at: Instant::now() + config.packet_expiration,
            kind: TimeoutKind::Outbound { token },
        }));
    }

    pub fn enqueue_control_frame(
        &mut self,
        config: &EngineConfig,
        key: StreamKey,
        control: &mut StreamControl,
        frame: StreamFrame,
        attempt: u8,
    ) {
        let packet_id = self.next_packet_id();
        control.awaiting = Some(AwaitingPacket {
            packet_id,
            frame: AwaitingFrame::Control(frame.clone()),
            attempt,
        });
        let valid_until =
            crate::wire::now_secs().saturating_add(config.packet_expiration.as_secs());
        self.enqueue_stream_body(
            config,
            Some(key.stream_id),
            Some(packet_id),
            true,
            false,
            StreamBody {
                packet_id,
                valid_until,
                packet_ack: None,
                frame: Some(frame),
            },
        );
    }

    pub fn enqueue_data_frame(
        &mut self,
        config: &EngineConfig,
        key: StreamKey,
        control: &mut StreamControl,
        dir: Direction,
        offset: u64,
        bytes: Vec<u8>,
        attempt: u8,
    ) {
        let packet_id = self.next_packet_id();
        control.awaiting = Some(AwaitingPacket {
            packet_id,
            frame: AwaitingFrame::Data {
                dir,
                offset,
                len: bytes.len(),
            },
            attempt,
        });
        let valid_until =
            crate::wire::now_secs().saturating_add(config.packet_expiration.as_secs());
        self.enqueue_stream_body(
            config,
            Some(key.stream_id),
            Some(packet_id),
            true,
            false,
            StreamBody {
                packet_id,
                valid_until,
                packet_ack: None,
                frame: Some(StreamFrame::Data(StreamFrameData {
                    stream_id: key.stream_id,
                    dir,
                    offset,
                    bytes,
                })),
            },
        );
    }
}

pub enum EitherRetransmit {
    Control(StreamFrame),
    Data {
        dir: Direction,
        offset: u64,
        len: usize,
    },
}
