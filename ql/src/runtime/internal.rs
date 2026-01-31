use std::{
    cell::Cell,
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, VecDeque},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use bc_components::{EncapsulationPublicKey, SigningPublicKey, SymmetricKey, XID};
use dcbor::CBOR;

use crate::{
    platform::PlatformFuture,
    runtime::{replay_cache::ReplayCache, RequestConfig},
    wire::{
        handshake::{Hello, HelloReply},
        message::MessageKind,
    },
    MessageId, QlError, RouteId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token(u64);

impl Token {
    pub(crate) fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

#[derive(Debug, Clone)]
pub struct KeepAliveState {
    pub token: Token,
    pub pending: bool,
    pub last_activity: Option<Instant>,
}

impl KeepAliveState {
    pub fn new() -> Self {
        Self {
            token: Token(0),
            pending: false,
            last_activity: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub peer: XID,
    pub signing_key: SigningPublicKey,
    pub encapsulation_key: EncapsulationPublicKey,
    pub session: PeerSession,
}

impl PeerRecord {
    pub fn new(
        peer: XID,
        signing_key: SigningPublicKey,
        encapsulation_key: EncapsulationPublicKey,
    ) -> Self {
        Self {
            peer,
            signing_key,
            encapsulation_key,
            session: PeerSession::Disconnected,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerStore {
    peers: Vec<PeerRecord>,
}

impl PeerStore {
    pub fn new() -> Self {
        Self { peers: Vec::new() }
    }

    pub fn peer(&self, peer: XID) -> Option<&PeerRecord> {
        self.peers.iter().find(|record| record.peer == peer)
    }

    pub fn peer_mut(&mut self, peer: XID) -> Option<&mut PeerRecord> {
        self.peers.iter_mut().find(|record| record.peer == peer)
    }

    pub fn upsert_peer(
        &mut self,
        peer: XID,
        signing_key: SigningPublicKey,
        encapsulation_key: EncapsulationPublicKey,
    ) -> &mut PeerRecord {
        if let Some(index) = self.peers.iter().position(|record| record.peer == peer) {
            let record = &mut self.peers[index];
            record.signing_key = signing_key;
            record.encapsulation_key = encapsulation_key;
            return record;
        }
        self.peers
            .push(PeerRecord::new(peer, signing_key, encapsulation_key));
        self.peers.last_mut().expect("peer record just inserted")
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
        secrets: crate::crypto::handshake::ResponderSecrets,
        deadline: Instant,
    },
    Connected {
        session_key: SymmetricKey,
        keepalive: KeepAliveState,
    },
}

impl PeerSession {
    #[inline]
    pub fn is_connected(&self) -> bool {
        match self {
            PeerSession::Connected { .. } => true,
            _ => false,
        }
    }

    #[inline]
    pub fn session_key(&self) -> Option<&SymmetricKey> {
        match self {
            PeerSession::Connected { session_key, .. } => Some(session_key),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitiatorStage {
    WaitingHelloReply,
    WaitingConfirmAck,
}

pub(crate) enum RuntimeCommand {
    RegisterPeer {
        peer: XID,
        signing_key: SigningPublicKey,
        encapsulation_key: EncapsulationPublicKey,
    },
    Connect {
        peer: XID,
    },
    SendRequest {
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
        respond_to: oneshot::Sender<Result<CBOR, QlError>>,
        config: RequestConfig,
    },
    SendEvent {
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
    },
    SendResponse {
        id: MessageId,
        recipient: XID,
        payload: CBOR,
        kind: MessageKind,
    },
    Incoming(Vec<u8>),
}

pub struct RuntimeState {
    pub peers: PeerStore,
    pub next_token: Cell<Token>,
    pub outbound: VecDeque<OutboundMessage>,
    pub timeouts: BinaryHeap<Reverse<TimeoutEntry>>,
    pub pending: HashMap<MessageId, PendingEntry>,
    pub next_message_id: u64,
    pub replay_cache: ReplayCache,
}

impl RuntimeState {
    pub fn new() -> Self {
        Self {
            peers: PeerStore::new(),
            next_token: Cell::new(Token(0)),
            outbound: VecDeque::new(),
            timeouts: BinaryHeap::new(),
            pending: HashMap::new(),
            next_message_id: 1,
            replay_cache: ReplayCache::new(),
        }
    }

    pub fn next_token(&self) -> Token {
        let token = self.next_token.get();
        self.next_token.set(token.next());
        token
    }

    pub fn next_message_id(&mut self) -> MessageId {
        let id = self.next_message_id;
        self.next_message_id = id.wrapping_add(1);
        MessageId::new(id)
    }
}

pub struct PendingEntry {
    pub recipient: XID,
    pub tx: oneshot::Sender<Result<CBOR, QlError>>,
}

pub struct InFlightWrite<'a> {
    pub peer: XID,
    pub token: Token,
    pub message_id: Option<MessageId>,
    pub future: PlatformFuture<'a, Result<(), QlError>>,
}

pub struct OutboundMessage {
    pub peer: XID,
    pub token: Token,
    pub message_id: Option<MessageId>,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutKind {
    Outbound { token: Token },
    Handshake { peer: XID, token: Token },
    Request { id: MessageId },
    KeepAliveSend { peer: XID, token: Token },
    KeepAliveTimeout { peer: XID, token: Token },
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

pub enum LoopStep {
    Event(RuntimeCommand),
    Timeout,
    WriteDone {
        peer: XID,
        token: Token,
        message_id: Option<MessageId>,
        result: Result<(), QlError>,
    },
    Quit,
}

pub enum HelloAction {
    StartResponder,
    ResendReply {
        reply: HelloReply,
        deadline: Instant,
    },
    Ignore,
}

pub fn next_timeout_deadline(state: &RuntimeState) -> Option<Instant> {
    state.timeouts.peek().map(|entry| entry.0.at)
}

pub fn peer_hello_wins(
    local_hello: &Hello,
    local_sender: XID,
    peer_hello: &Hello,
    peer_sender: XID,
) -> bool {
    use std::cmp::Ordering;

    match peer_hello.nonce.data().cmp(local_hello.nonce.data()) {
        Ordering::Less => true,
        Ordering::Greater => false,
        Ordering::Equal => peer_sender.data().cmp(local_sender.data()) == Ordering::Less,
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
