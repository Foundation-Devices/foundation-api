use std::{
    cell::Cell,
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, VecDeque},
    time::Instant,
};

use bc_components::{MLDSAPublicKey, MLKEMPublicKey, SymmetricKey, XID};

use super::{
    EngineConfig, StreamConfig,
    replay_cache::ReplayCache,
    stream::{QueuedWrite, StreamState},
};
use crate::{
    PacketId, Peer, QlError, StreamId, StreamSeq,
    wire::{
        handshake::{Hello, HelloReply, ResponderSecrets},
        stream::{BodyChunk, Direction, RejectCode, ResetCode, StreamBody},
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpenId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackedWrite {
    pub stream_id: StreamId,
    pub tx_seq: StreamSeq,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamNamespace {
    Low,
    High,
}

impl StreamNamespace {
    const BIT: u64 = 1 << 63;

    pub fn bit(self) -> u64 {
        match self {
            Self::Low => 0,
            Self::High => Self::BIT,
        }
    }

    pub fn for_local(local: XID, peer: XID) -> Self {
        match local.data().cmp(peer.data()) {
            std::cmp::Ordering::Less | std::cmp::Ordering::Equal => Self::Low,
            std::cmp::Ordering::Greater => Self::High,
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
        request_prefix: Option<BodyChunk>,
        config: StreamConfig,
    },
    AcceptStream {
        stream_id: StreamId,
        response_head: Vec<u8>,
        response_prefix: Option<BodyChunk>,
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
        response_prefix: Option<BodyChunk>,
    },
    OpenFailed {
        open_id: OpenId,
        stream_id: StreamId,
        error: QlError,
    },

    InboundStreamOpened {
        stream_id: StreamId,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
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
    StreamMessage {
        stream_id: StreamId,
        tx_seq: StreamSeq,
        attempt: u8,
    },
    StreamAckDelay {
        stream_id: StreamId,
        token: Token,
    },
    StreamProvisional {
        stream_id: StreamId,
        token: Token,
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
    pub local_xid: XID,
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

    pub fn next_stream_id(&self, namespace: StreamNamespace) -> StreamId {
        let seq = self.next_stream_id.get();
        self.next_stream_id.set(seq.wrapping_add(1));
        StreamId((seq & !StreamNamespace::BIT) | namespace.bit())
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
        priority: bool,
        body: StreamBody,
    ) -> Token {
        let token = self.next_token();
        let message = QueuedWrite {
            token,
            payload: super::stream::QueuedPayload::Stream { body },
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
        token
    }
}
