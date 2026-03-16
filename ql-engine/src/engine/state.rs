use std::{
    cell::Cell,
    cmp::Reverse,
    collections::{BinaryHeap, VecDeque},
    time::Instant,
};

use bc_components::{MLDSAPublicKey, MLKEMPublicKey, SymmetricKey, XID};

use super::{replay_cache::ReplayCache, EngineConfig};
use crate::{
    arena::{ArenaKey, GenerationalArena},
    identity::QlIdentity,
    stream::{self, StreamFsm},
    wire::handshake::{Confirm, Hello, HelloReply, Ready, ResponderSecrets},
    PacketId, Peer,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WriteId(pub(crate) ArenaKey);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundWriteKind {
    Control,
    Stream(stream::OutboundCompletion),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundWrite {
    pub id: WriteId,
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct ControlWrite {
    pub token: Token,
    pub bytes: Vec<u8>,
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

#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeInitiator {
    WaitingHelloReply {
        retry_count: u8,
        retry_at: Option<Instant>,
    },
    WaitingReady {
        reply: HelloReply,
        confirm: Confirm,
        retry_count: u8,
        retry_at: Option<Instant>,
    },
}

#[derive(Debug, Clone)]
pub enum HandshakeResponder {
    WaitingConfirm {
        secrets: ResponderSecrets,
        retry_count: u8,
        retry_at: Option<Instant>,
    },
    SendingReady {
        session_key: SymmetricKey,
        ready: Ready,
    },
}

#[derive(Debug, Clone)]
pub struct RecentReady {
    pub hello: Hello,
    pub reply: HelloReply,
    pub ready: Ready,
    pub expires_at: Instant,
}

#[derive(Debug, Clone)]
pub enum PeerSession {
    Disconnected,
    Initiator {
        handshake_token: Token,
        hello: Hello,
        session_key: SymmetricKey,
        deadline: Instant,
        stage: HandshakeInitiator,
    },
    Responder {
        handshake_token: Token,
        hello: Hello,
        reply: HelloReply,
        deadline: Instant,
        stage: HandshakeResponder,
    },
    Connected {
        session_key: SymmetricKey,
        keepalive: KeepAliveState,
        recent_ready: Option<RecentReady>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutKind {
    Outbound { token: Token },
    HandshakeRetry { token: Token },
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

pub struct Engine {
    pub config: EngineConfig,
    pub identity: QlIdentity,
    pub peer: Option<PeerRecord>,
    pub state: EngineState,
    pub streams: StreamFsm,
}

pub struct EngineState {
    pub replay_cache: ReplayCache,

    pub next_token: Cell<u64>,
    pub next_packet_id: Cell<u32>,
    pub control_outbound: VecDeque<ControlWrite>,
    pub active_writes: GenerationalArena<ActiveWrite>,
    pub timeouts: BinaryHeap<Reverse<TimeoutEntry>>,
    pub now: Instant,
}

impl EngineState {
    pub fn new() -> Self {
        Self {
            replay_cache: ReplayCache::new(),
            next_token: Cell::new(1),
            next_packet_id: Cell::new(1),
            control_outbound: VecDeque::new(),
            active_writes: GenerationalArena::new(),
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

    pub fn next_packet_id(&self) -> PacketId {
        let id = self.next_packet_id.get();
        self.next_packet_id.set(id.wrapping_add(1));
        PacketId(id)
    }

    pub fn enqueue_handshake_message(
        &mut self,
        _config: &EngineConfig,
        token: Token,
        deadline: Instant,
        bytes: Vec<u8>,
    ) {
        self.control_outbound
            .push_back(ControlWrite { token, bytes });
        self.timeouts.push(Reverse(TimeoutEntry {
            at: deadline,
            kind: TimeoutKind::Outbound { token },
        }));
    }

    pub fn schedule_handshake_retry(&mut self, token: Token, at: Instant) {
        self.timeouts.push(Reverse(TimeoutEntry {
            at,
            kind: TimeoutKind::HandshakeRetry { token },
        }));
    }

    pub fn enqueue_control(
        &mut self,
        config: &EngineConfig,
        priority: bool,
        bytes: Vec<u8>,
    ) -> Token {
        let token = self.next_token();
        let message = ControlWrite { token, bytes };
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
