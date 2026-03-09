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
    runtime::{replay_cache::ReplayCache, AcceptedStreamDelivery, StreamConfig},
    wire::{
        handshake::{Hello, HelloReply},
        stream::{
            Direction, OpenFlags, RejectCode, ResetCode, ResetTarget, StreamBody, StreamFrame,
            StreamFrameAccept, StreamFrameCredit, StreamFrameOpen, StreamFrameReset,
        },
    },
    PacketId, Peer, QlError, RouteId, StreamId,
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
pub enum StreamRole {
    Initiator,
    Responder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamPhase {
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
    Control(StreamFrame),
    Data {
        dir: Direction,
        offset: u64,
        len: usize,
    },
}

pub struct PendingStreamFrames {
    pub setup: Option<SetupFrame>,
    pub credit: Option<StreamFrameCredit>,
    pub reset: Option<StreamFrameReset>,
}

pub enum SetupFrame {
    Open(StreamFrameOpen),
    Accept(StreamFrameAccept),
}

impl PendingStreamFrames {
    pub fn new() -> Self {
        Self {
            setup: None,
            credit: None,
            reset: None,
        }
    }

    pub fn take_next_control(&mut self, stream_id: StreamId) -> Option<StreamFrame> {
        if let Some(setup) = self.setup.take() {
            return Some(match setup {
                SetupFrame::Open(frame) => StreamFrame::Open(frame),
                SetupFrame::Accept(frame) => StreamFrame::Accept(frame),
            });
        }
        if let Some(reset) = self.reset.take() {
            return Some(StreamFrame::Reset(StreamFrameReset { stream_id, ..reset }));
        }
        self.credit.take().map(StreamFrame::Credit)
    }

    pub fn set_setup(&mut self, frame: SetupFrame) {
        self.setup = Some(frame);
    }

    pub fn set_credit(&mut self, frame: StreamFrameCredit) {
        if self.reset.is_none() {
            self.credit = Some(frame);
        }
    }

    pub fn set_reset(&mut self, dir: ResetTarget, code: ResetCode) {
        self.credit = None;
        self.reset = Some(StreamFrameReset {
            stream_id: StreamId(0),
            dir,
            code,
        });
    }

    pub fn clear(&mut self) {
        self.setup = None;
        self.credit = None;
        self.reset = None;
    }
}

pub struct OutboundStreamState {
    pub dir: Direction,
    pub pipe: pipe::PipeReader,
    pub pending: PendingStreamFrames,
    pub awaiting: Option<AwaitingPacket>,
    pub remote_max_offset: u64,
    pub data_enabled: bool,
    pub closed: bool,
}

pub struct InboundStreamState {
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

pub struct StreamRecord {
    pub peer: XID,
    pub stream_id: StreamId,
    pub route_id: RouteId,
    pub role: StreamRole,
    pub phase: StreamPhase,
    pub open_flags: OpenFlags,
    pub request_head: Vec<u8>,
    pub response_head: Option<Vec<u8>>,
    pub response_rx: Option<Receiver<InboundStreamItem>>,
    pub accept_tx: Option<oneshot::Sender<Result<AcceptedStreamDelivery, QlError>>>,
    pub open_timeout_token: Token,
    pub initial_remote_credit: u64,
    pub outbound: Option<OutboundStreamState>,
    pub inbound: InboundStreamState,
    pub accept_frame: Option<StreamFrameAccept>,
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
    OpenStream {
        recipient: XID,
        route_id: RouteId,
        request_head: Vec<u8>,
        response_expected: bool,
        request_pipe: pipe::PipeReader,
        accepted: oneshot::Sender<Result<AcceptedStreamDelivery, QlError>>,
        start: oneshot::Sender<Result<StreamId, QlError>>,
        config: StreamConfig,
    },
    AcceptStream {
        recipient: XID,
        stream_id: StreamId,
        response_head: Vec<u8>,
        response_pipe: pipe::PipeReader,
    },
    RejectStream {
        recipient: XID,
        stream_id: StreamId,
        code: RejectCode,
    },
    PollStream {
        peer: XID,
        stream_id: StreamId,
    },
    AdvanceInboundCredit {
        sender: XID,
        stream_id: StreamId,
        dir: Direction,
        amount: u64,
    },
    ResetOutbound {
        recipient: XID,
        stream_id: StreamId,
        dir: Direction,
        code: ResetCode,
    },
    ResetInbound {
        sender: XID,
        stream_id: StreamId,
        dir: Direction,
        code: ResetCode,
    },
    Incoming(Vec<u8>),
}

pub struct StreamState {
    by_id: HashMap<(XID, StreamId), StreamRecord>,
}

impl StreamState {
    pub fn new() -> Self {
        Self {
            by_id: HashMap::new(),
        }
    }

    pub fn get(&self, key: &(XID, StreamId)) -> Option<&StreamRecord> {
        self.by_id.get(key)
    }

    pub fn get_mut(&mut self, key: &(XID, StreamId)) -> Option<&mut StreamRecord> {
        self.by_id.get_mut(key)
    }

    pub fn insert(&mut self, key: (XID, StreamId), stream: StreamRecord) -> Option<StreamRecord> {
        self.by_id.insert(key, stream)
    }

    pub fn remove(&mut self, key: &(XID, StreamId)) -> Option<StreamRecord> {
        self.by_id.remove(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &(XID, StreamId)> {
        self.by_id.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&(XID, StreamId), &StreamRecord)> {
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

    pub fn next_stream_id(&self) -> StreamId {
        let id = self.next_id.get();
        self.next_id.set(id.wrapping_add(1));
        StreamId(id)
    }
}

pub struct RuntimeState {
    pub stream: StreamState,
    pub core: CoreState,
}

impl RuntimeState {
    pub fn new() -> Self {
        Self {
            stream: StreamState::new(),
            core: CoreState::new(),
        }
    }
}

pub struct InFlightWrite<'a> {
    pub peer: XID,
    pub token: Token,
    pub stream_id: Option<StreamId>,
    pub packet_id: Option<PacketId>,
    pub track_ack: bool,
    pub future: PlatformFuture<'a, Result<(), QlError>>,
}

pub enum OutboundPayload {
    PreEncoded(Vec<u8>),
    DeferredStream(StreamBody),
}

pub struct OutboundMessage {
    pub peer: XID,
    pub token: Token,
    pub stream_id: Option<StreamId>,
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
    StreamOpen {
        peer: XID,
        stream_id: StreamId,
        token: Token,
    },
    StreamPacket {
        peer: XID,
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

pub enum LoopStep {
    Event(RuntimeCommand),
    Timeout,
    WriteDone {
        peer: XID,
        token: Token,
        stream_id: Option<StreamId>,
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

impl StreamRecord {
    pub fn local_outbound_dir(&self) -> Direction {
        match self.role {
            StreamRole::Initiator => Direction::Request,
            StreamRole::Responder => Direction::Response,
        }
    }
}

impl OutboundStreamState {
    pub fn new(dir: Direction, pipe: pipe::PipeReader, remote_max_offset: u64) -> Self {
        Self {
            dir,
            pipe,
            pending: PendingStreamFrames::new(),
            awaiting: None,
            remote_max_offset,
            data_enabled: false,
            closed: false,
        }
    }
}

impl InboundStreamState {
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
