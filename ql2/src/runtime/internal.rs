use std::{
    cell::Cell,
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, VecDeque},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use async_channel::{Receiver, Sender};
use bc_components::{MLDSAPublicKey, MLKEMPublicKey, SymmetricKey, XID};

use crate::{
    pipe,
    platform::PlatformFuture,
    runtime::{replay_cache::ReplayCache, AcceptedCallDelivery, CallConfig},
    wire::{
        call::{CallBody, CallFrame, Direction, OpenFlags, RejectCode, ResetCode},
        handshake::{Hello, HelloReply},
    },
    CallId, PacketId, Peer, QlError, RouteId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token(pub u64);

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

impl Default for KeepAliveState {
    fn default() -> Self {
        Self::new()
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
        signing_key: MLDSAPublicKey,
        encapsulation_key: MLKEMPublicKey,
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

    pub fn all(&self) -> Vec<Peer> {
        self.peers
            .iter()
            .map(|record| Peer {
                peer: record.peer,
                signing_key: record.signing_key.clone(),
                encapsulation_key: record.encapsulation_key.clone(),
            })
            .collect()
    }

    pub fn remove_peer(&mut self, peer: XID) -> Option<PeerRecord> {
        let index = self.peers.iter().position(|record| record.peer == peer)?;
        Some(self.peers.remove(index))
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
        secrets: crate::wire::handshake::ResponderSecrets,
        deadline: Instant,
    },
    Connected {
        session_key: SymmetricKey,
        keepalive: KeepAliveState,
    },
}

impl PeerSession {
    pub fn is_connected(&self) -> bool {
        matches!(self, PeerSession::Connected { .. })
    }

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

pub(crate) enum InboundStreamItem {
    Chunk(Vec<u8>),
    Finished,
    Error(QlError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallRole {
    Initiator,
    Responder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallPhase {
    InitiatorOpening,
    InitiatorWaitingAccept,
    ResponderPending,
    ResponderAccepting,
    Open,
    Rejected,
    Closed,
}

pub struct AwaitingPacket {
    pub packet_id: PacketId,
    pub frame: AwaitingFrame,
    pub attempt: u8,
}

pub enum AwaitingFrame {
    Control(CallFrame),
    Data {
        dir: Direction,
        offset: u64,
        len: usize,
    },
}

pub struct OutboundCallStreamState {
    pub dir: Direction,
    pub pipe: pipe::PipeReader,
    pub queue: VecDeque<CallFrame>,
    pub awaiting: Option<AwaitingPacket>,
    pub remote_max_offset: u64,
    pub data_enabled: bool,
    pub closed: bool,
}

pub struct InboundCallStreamState {
    pub dir: Direction,
    pub chunk_tx: Sender<InboundStreamItem>,
    pub pending_chunk: Option<Vec<u8>>,
    pub next_offset: u64,
    pub max_offset: u64,
    pub terminal: Option<InboundTerminal>,
    pub closed: bool,
}

pub enum InboundTerminal {
    Finished,
    Error(QlError),
}

pub struct CallRecord {
    pub peer: XID,
    pub call_id: CallId,
    pub route_id: RouteId,
    pub role: CallRole,
    pub phase: CallPhase,
    pub open_flags: OpenFlags,
    pub request_head: Vec<u8>,
    pub response_head: Option<Vec<u8>>,
    pub response_rx: Option<Receiver<InboundStreamItem>>,
    pub accept_tx: Option<oneshot::Sender<Result<AcceptedCallDelivery, QlError>>>,
    pub open_timeout_token: Token,
    pub initial_remote_credit: u64,
    pub outbound: Option<OutboundCallStreamState>,
    pub inbound: InboundCallStreamState,
    pub accept_frame: Option<CallFrame>,
    pub last_activity: Instant,
}

pub(crate) enum RuntimeCommand {
    RegisterPeer {
        peer: XID,
        signing_key: MLDSAPublicKey,
        encapsulation_key: MLKEMPublicKey,
    },
    Connect {
        peer: XID,
    },
    Unpair {
        peer: XID,
    },
    OpenCall {
        recipient: XID,
        route_id: RouteId,
        request_head: Vec<u8>,
        response_expected: bool,
        request_pipe: pipe::PipeReader,
        accepted: oneshot::Sender<Result<AcceptedCallDelivery, QlError>>,
        start: oneshot::Sender<Result<CallId, QlError>>,
        config: CallConfig,
    },
    AcceptCall {
        recipient: XID,
        call_id: CallId,
        response_head: Vec<u8>,
        response_pipe: pipe::PipeReader,
    },
    RejectCall {
        recipient: XID,
        call_id: CallId,
        code: RejectCode,
    },
    PollCall {
        peer: XID,
        call_id: CallId,
    },
    AdvanceInboundCredit {
        sender: XID,
        call_id: CallId,
        dir: Direction,
        amount: u64,
    },
    ResetOutbound {
        recipient: XID,
        call_id: CallId,
        dir: Direction,
        code: ResetCode,
    },
    ResetInbound {
        sender: XID,
        call_id: CallId,
        dir: Direction,
        code: ResetCode,
    },
    Incoming(Vec<u8>),
}

pub struct CallState {
    by_id: HashMap<(XID, CallId), CallRecord>,
}

impl CallState {
    pub fn new() -> Self {
        Self {
            by_id: HashMap::new(),
        }
    }

    pub fn get(&self, key: &(XID, CallId)) -> Option<&CallRecord> {
        self.by_id.get(key)
    }

    pub fn get_mut(&mut self, key: &(XID, CallId)) -> Option<&mut CallRecord> {
        self.by_id.get_mut(key)
    }

    pub fn insert(&mut self, key: (XID, CallId), call: CallRecord) -> Option<CallRecord> {
        self.by_id.insert(key, call)
    }

    pub fn remove(&mut self, key: &(XID, CallId)) -> Option<CallRecord> {
        self.by_id.remove(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &(XID, CallId)> {
        self.by_id.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&(XID, CallId), &CallRecord)> {
        self.by_id.iter()
    }
}

pub struct CoreState {
    pub peers: PeerStore,
    pub next_token: Cell<Token>,
    pub outbound: VecDeque<OutboundMessage>,
    pub timeouts: BinaryHeap<Reverse<TimeoutEntry>>,
    pub next_id: Cell<u64>,
    pub replay_cache: ReplayCache,
}

impl CoreState {
    pub fn new() -> Self {
        Self {
            peers: PeerStore::new(),
            next_token: Cell::new(Token(1)),
            outbound: VecDeque::new(),
            timeouts: BinaryHeap::new(),
            next_id: Cell::new(1),
            replay_cache: ReplayCache::new(),
        }
    }

    pub fn next_token(&self) -> Token {
        let token = self.next_token.get();
        self.next_token.set(Token(token.0.wrapping_add(1)));
        token
    }

    pub fn next_packet_id(&self) -> PacketId {
        let id = self.next_id.get();
        self.next_id.set(id.wrapping_add(1));
        PacketId(id)
    }

    pub fn next_call_id(&self) -> CallId {
        let id = self.next_id.get();
        self.next_id.set(id.wrapping_add(1));
        CallId(id)
    }
}

pub struct RuntimeState {
    pub calls: CallState,
    pub core: CoreState,
}

impl RuntimeState {
    pub fn new() -> Self {
        Self {
            calls: CallState::new(),
            core: CoreState::new(),
        }
    }
}

pub struct InFlightWrite<'a> {
    pub peer: XID,
    pub token: Token,
    pub call_id: Option<CallId>,
    pub packet_id: Option<PacketId>,
    pub track_ack: bool,
    pub future: PlatformFuture<'a, Result<(), QlError>>,
}

pub enum OutboundPayload {
    PreEncoded(Vec<u8>),
    DeferredCall(CallBody),
}

pub struct OutboundMessage {
    pub peer: XID,
    pub token: Token,
    pub call_id: Option<CallId>,
    pub packet_id: Option<PacketId>,
    pub track_ack: bool,
    pub payload: OutboundPayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutKind {
    Outbound {
        token: Token,
    },
    Handshake {
        peer: XID,
        token: Token,
    },
    KeepAliveSend {
        peer: XID,
        token: Token,
    },
    KeepAliveTimeout {
        peer: XID,
        token: Token,
    },
    CallOpen {
        peer: XID,
        call_id: CallId,
        token: Token,
    },
    CallPacket {
        peer: XID,
        call_id: CallId,
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

pub enum LoopStep {
    Event(RuntimeCommand),
    Timeout,
    WriteDone {
        peer: XID,
        token: Token,
        call_id: Option<CallId>,
        packet_id: Option<PacketId>,
        track_ack: bool,
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

impl CallRecord {
    pub fn local_outbound_dir(&self) -> Direction {
        match self.role {
            CallRole::Initiator => Direction::Request,
            CallRole::Responder => Direction::Response,
        }
    }
}

impl OutboundCallStreamState {
    pub fn new(dir: Direction, pipe: pipe::PipeReader, remote_max_offset: u64) -> Self {
        Self {
            dir,
            pipe,
            queue: VecDeque::new(),
            awaiting: None,
            remote_max_offset,
            data_enabled: false,
            closed: false,
        }
    }
}

impl InboundCallStreamState {
    pub fn new(dir: Direction, chunk_tx: Sender<InboundStreamItem>, max_offset: u64) -> Self {
        Self {
            dir,
            chunk_tx,
            pending_chunk: None,
            next_offset: 0,
            max_offset,
            terminal: None,
            closed: false,
        }
    }
}
