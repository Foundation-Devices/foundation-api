use std::{
    cell::Cell,
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, VecDeque},
    time::Instant,
};

use bc_components::{MLDSAPublicKey, MLKEMPublicKey, SymmetricKey, XID};

use super::{replay_cache::ReplayCache, stream::StreamStore, EngineConfig, StreamConfig};
use crate::{
    platform::QlIdentity,
    wire::{
        handshake::{Hello, HelloReply, ResponderSecrets},
        stream::{BodyChunk, Direction, RejectCode, ResetCode, ResetTarget},
        StreamSeq,
    },
    PacketId, Peer, QlError, StreamId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpenId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WriteId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundWriteKind {
    Control,
    StreamAck {
        stream_id: StreamId,
    },
    StreamFrame {
        stream_id: StreamId,
        tx_seq: StreamSeq,
    },
    StreamReset {
        stream_id: StreamId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundWrite {
    pub id: WriteId,
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct ControlWrite {
    pub token: Token,
    pub kind: OutboundWriteKind,
    pub payload: ControlWritePayload,
}

#[derive(Debug)]
pub enum ControlWritePayload {
    Encoded(Vec<u8>),
    StreamReset {
        stream_id: StreamId,
        target: ResetTarget,
        code: ResetCode,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct ActiveWrite {
    pub token: Option<Token>,
    pub kind: OutboundWriteKind,
}

#[derive(Debug, Clone)]
pub struct KeepAliveState {
    pub pending: bool,
    pub last_activity: Option<Instant>,
}

impl Default for KeepAliveState {
    fn default() -> Self {
        Self {
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
        bytes: Vec<u8>,
    },
    OutboundFinished {
        stream_id: StreamId,
        dir: Direction,
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
    TimerExpired,
}

#[derive(Debug)]
pub enum EngineOutput {
    SetTimer(Option<Instant>),

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
    Outbound { token: Token },
    Handshake { token: Token },
    StreamOpen { stream_id: StreamId, token: Token },
    StreamAckDelay { stream_id: StreamId, token: Token },
    StreamProvisional { stream_id: StreamId, token: Token },
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
    pub identity: QlIdentity,
    pub peer: Option<PeerRecord>,
    pub state: EngineState,
    pub streams: StreamStore,
}

pub struct EngineState {
    pub replay_cache: ReplayCache,

    pub next_token: Cell<u64>,
    pub next_write_id: Cell<u64>,
    pub next_packet_id: Cell<u32>,
    pub next_stream_id: Cell<u64>,
    pub control_outbound: VecDeque<ControlWrite>,
    pub active_writes: HashMap<WriteId, ActiveWrite>,
    pub timeouts: BinaryHeap<Reverse<TimeoutEntry>>,
    pub now: Instant,
}

impl EngineState {
    pub fn new() -> Self {
        Self {
            replay_cache: ReplayCache::new(),
            next_token: Cell::new(1),
            next_write_id: Cell::new(1),
            next_packet_id: Cell::new(1),
            next_stream_id: Cell::new(1),
            control_outbound: VecDeque::new(),
            active_writes: HashMap::new(),
            timeouts: BinaryHeap::new(),
            now: Instant::now(),
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

    pub fn next_write_id(&self) -> WriteId {
        let id = self.next_write_id.get();
        self.next_write_id.set(id.wrapping_add(1));
        WriteId(id)
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
        self.control_outbound.push_back(ControlWrite {
            token,
            kind: OutboundWriteKind::Control,
            payload: ControlWritePayload::Encoded(bytes),
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

    pub fn enqueue_control(
        &mut self,
        config: &EngineConfig,
        priority: bool,
        bytes: Vec<u8>,
    ) -> Token {
        let token = self.next_token();
        let message = ControlWrite {
            token,
            kind: OutboundWriteKind::Control,
            payload: ControlWritePayload::Encoded(bytes),
        };
        if priority {
            self.control_outbound.push_front(message);
        } else {
            self.control_outbound.push_back(message);
        }
        self.timeouts.push(Reverse(TimeoutEntry {
            at: self.now + config.packet_expiration,
            kind: TimeoutKind::Outbound { token },
        }));
        token
    }

    pub fn enqueue_stream_reset(
        &mut self,
        config: &EngineConfig,
        priority: bool,
        stream_id: StreamId,
        target: ResetTarget,
        code: ResetCode,
    ) -> Token {
        let token = self.next_token();
        let message = ControlWrite {
            token,
            kind: OutboundWriteKind::StreamReset { stream_id },
            payload: ControlWritePayload::StreamReset {
                stream_id,
                target,
                code,
            },
        };
        if priority {
            self.control_outbound.push_front(message);
        } else {
            self.control_outbound.push_back(message);
        }
        self.timeouts.push(Reverse(TimeoutEntry {
            at: self.now + config.packet_expiration,
            kind: TimeoutKind::Outbound { token },
        }));
        token
    }
}
