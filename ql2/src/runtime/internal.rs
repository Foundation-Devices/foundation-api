use std::{
    cell::Cell,
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, VecDeque},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use bc_components::{MLDSAPublicKey, MLKEMPublicKey, SymmetricKey, XID};

use crate::{
    pipe,
    platform::PlatformFuture,
    runtime::{replay_cache::ReplayCache, AcceptedStreamDelivery, StreamConfig},
    wire::{
        handshake::{Hello, HelloReply},
        stream::{
            Direction, RejectCode, ResetCode, ResetTarget, StreamBody, StreamFrame,
            StreamFrameAccept, StreamFrameCredit, StreamFrameOpen, StreamFrameReject,
            StreamFrameReset,
        },
    },
    ConnectionId, PacketId, Peer, QlError, StreamId,
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
        cid: Option<ConnectionId>,
        handshake_token: Token,
        hello: Hello,
        session_key: SymmetricKey,
        deadline: Instant,
        stage: InitiatorStage,
    },
    Responder {
        cid: ConnectionId,
        handshake_token: Token,
        hello: Hello,
        reply: HelloReply,
        secrets: crate::wire::handshake::ResponderSecrets,
        deadline: Instant,
    },
    Connected {
        cid: ConnectionId,
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

    pub fn connection_id(&self) -> Option<ConnectionId> {
        match self {
            PeerSession::Disconnected => None,
            PeerSession::Initiator { cid, .. } => *cid,
            PeerSession::Responder { cid, .. } | PeerSession::Connected { cid, .. } => Some(*cid),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitiatorStage {
    WaitingHelloReply,
    WaitingConfirmAck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamKey {
    pub peer: XID,
    pub stream_id: StreamId,
}

#[derive(Debug)]
pub struct StreamMeta {
    pub key: StreamKey,
    pub request_head: Vec<u8>,
    pub last_activity: Instant,
}

pub struct PendingAcceptTx {
    pub tx: Option<oneshot::Sender<Result<AcceptedStreamDelivery, QlError>>>,
    pub response_reader: Option<pipe::PipeReader<QlError>>,
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

pub enum SetupFrame {
    Open(StreamFrameOpen),
    Accept(StreamFrameAccept),
    Reject(StreamFrameReject),
}

pub struct PendingFrames {
    pub setup: Option<SetupFrame>,
    pub credit: Option<StreamFrameCredit>,
    pub reset: Option<StreamFrameReset>,
}

impl PendingFrames {
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
                SetupFrame::Reject(frame) => StreamFrame::Reject(frame),
            });
        }
        if let Some(reset) = self.reset.take() {
            return Some(StreamFrame::Reset(StreamFrameReset { stream_id, ..reset }));
        }
        self.credit.take().map(StreamFrame::Credit)
    }

    pub fn set_setup(&mut self, setup: SetupFrame) {
        self.setup = Some(setup);
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

    pub fn is_empty(&self) -> bool {
        self.setup.is_none() && self.credit.is_none() && self.reset.is_none()
    }
}

pub struct StreamControl {
    pub pending: PendingFrames,
    pub awaiting: Option<AwaitingPacket>,
}

impl StreamControl {
    pub fn new() -> Self {
        Self {
            pending: PendingFrames::new(),
            awaiting: None,
        }
    }
}

pub struct OutboundBody {
    pub dir: Direction,
    pub pipe: pipe::PipeReader<QlError>,
    pub remote_max_offset: u64,
    pub data_enabled: bool,
    /// Tracks terminal inbound transition for this stream half.
    /// Separate from the pipe state because the pipe can be locally closed before the
    /// runtime has finished scheduling the matching `Finish` or `Reset` frame.
    pub closed: bool,
}

impl OutboundBody {
    pub fn new(
        dir: Direction,
        pipe: pipe::PipeReader<QlError>,
        remote_max_offset: u64,
        data_enabled: bool,
    ) -> Self {
        Self {
            dir,
            pipe,
            remote_max_offset,
            data_enabled,
            closed: false,
        }
    }
}

pub struct InboundBody {
    pub pipe: pipe::PipeWriter<QlError>,
    pub next_offset: u64,
    pub max_offset: u64,
    /// Tracks terminal inbound transition for this stream half.
    /// Separate from the pipe state because the pipe can be locally closed
    /// first, and the runtime still needs to emit or suppress the corresponding protocol action.
    pub closed: bool,
}

impl InboundBody {
    pub fn new(pipe: pipe::PipeWriter<QlError>, max_offset: u64) -> Self {
        Self {
            pipe,
            next_offset: 0,
            max_offset,
            closed: false,
        }
    }
}

pub struct InitiatorStream {
    pub meta: StreamMeta,
    pub control: StreamControl,
    pub request: OutboundBody,
    pub response: InboundBody,
    pub accept: InitiatorAccept,
}

pub enum InitiatorAccept {
    Opening {
        accept_waiter: Option<PendingAcceptTx>,
        open_timeout_token: Token,
    },
    WaitingAccept {
        accept_waiter: Option<PendingAcceptTx>,
        open_timeout_token: Token,
    },
    Open {
        response_head: Vec<u8>,
    },
}

pub struct ResponderStream {
    pub meta: StreamMeta,
    pub control: StreamControl,
    pub request: InboundBody,
    pub response: ResponderResponse,
}

pub enum ResponderResponse {
    Pending {
        initial_credit: u64,
    },
    Accepted {
        initial_credit: u64,
        body: OutboundBody,
    },
    Rejecting {
        initial_credit: u64,
    },
}

pub enum StreamState {
    Initiator(InitiatorStream),
    Responder(ResponderStream),
}

impl StreamState {
    pub fn key(&self) -> StreamKey {
        match self {
            Self::Initiator(state) => state.meta.key,
            Self::Responder(state) => state.meta.key,
        }
    }

    pub fn last_activity_mut(&mut self) -> &mut Instant {
        match self {
            Self::Initiator(state) => &mut state.meta.last_activity,
            Self::Responder(state) => &mut state.meta.last_activity,
        }
    }

    pub fn control(&self) -> &StreamControl {
        match self {
            Self::Initiator(state) => &state.control,
            Self::Responder(state) => &state.control,
        }
    }

    pub fn control_mut(&mut self) -> &mut StreamControl {
        match self {
            Self::Initiator(state) => &mut state.control,
            Self::Responder(state) => &mut state.control,
        }
    }

    pub fn outbound_mut(&mut self, dir: Direction) -> Option<&mut OutboundBody> {
        match self {
            Self::Initiator(state) if dir == Direction::Request => Some(&mut state.request),
            Self::Responder(state) if dir == Direction::Response => match &mut state.response {
                ResponderResponse::Accepted { body, .. } => Some(body),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn inbound_mut(&mut self, dir: Direction) -> Option<&mut InboundBody> {
        match self {
            Self::Initiator(state) if dir == Direction::Response => Some(&mut state.response),
            Self::Responder(state) if dir == Direction::Request => Some(&mut state.request),
            _ => None,
        }
    }

    pub fn open_timeout_token(&self) -> Option<Token> {
        match self {
            Self::Initiator(state) => match &state.accept {
                InitiatorAccept::Opening {
                    open_timeout_token, ..
                }
                | InitiatorAccept::WaitingAccept {
                    open_timeout_token, ..
                } => Some(*open_timeout_token),
                InitiatorAccept::Open { .. } => None,
            },
            _ => None,
        }
    }

    pub fn can_reap(&self) -> bool {
        if self.control().awaiting.is_some() || !self.control().pending.is_empty() {
            return false;
        }
        match self {
            Self::Initiator(state) => {
                matches!(state.accept, InitiatorAccept::Open { .. })
                    && state.request.closed
                    && state.response.closed
            }
            Self::Responder(state) => match &state.response {
                ResponderResponse::Accepted { body, .. } => state.request.closed && body.closed,
                ResponderResponse::Rejecting { .. } => true,
                _ => false,
            },
        }
    }
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
        request_head: Vec<u8>,
        request_pipe: pipe::PipeReader<QlError>,
        accepted: oneshot::Sender<Result<AcceptedStreamDelivery, QlError>>,
        start: oneshot::Sender<Result<StreamId, QlError>>,
        config: StreamConfig,
    },
    AcceptStream {
        recipient: XID,
        stream_id: StreamId,
        response_head: Vec<u8>,
        response_pipe: pipe::PipeReader<QlError>,
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
    ResponderDropped {
        sender: XID,
        stream_id: StreamId,
    },
    PendingAcceptDropped {
        recipient: XID,
        stream_id: StreamId,
    },
    Incoming {
        cid: ConnectionId,
        bytes: Vec<u8>,
    },
}

pub struct StreamStore {
    by_id: HashMap<(XID, StreamId), StreamState>,
}

impl StreamStore {
    pub fn new() -> Self {
        Self {
            by_id: HashMap::new(),
        }
    }

    pub fn get(&self, key: &(XID, StreamId)) -> Option<&StreamState> {
        self.by_id.get(key)
    }

    pub fn get_mut(&mut self, key: &(XID, StreamId)) -> Option<&mut StreamState> {
        self.by_id.get_mut(key)
    }

    pub fn insert(&mut self, key: (XID, StreamId), stream: StreamState) -> Option<StreamState> {
        self.by_id.insert(key, stream)
    }

    pub fn remove(&mut self, key: &(XID, StreamId)) -> Option<StreamState> {
        self.by_id.remove(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &(XID, StreamId)> {
        self.by_id.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&(XID, StreamId), &StreamState)> {
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
    pub streams: StreamStore,
    pub core: CoreState,
}

impl RuntimeState {
    pub fn new() -> Self {
        Self {
            streams: StreamStore::new(),
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
    pub cid: Option<ConnectionId>,
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
        cid: ConnectionId,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn stream_key() -> StreamKey {
        StreamKey {
            peer: XID::from_data([7; XID::XID_SIZE]),
            stream_id: StreamId(42),
        }
    }

    fn stream_meta() -> StreamMeta {
        StreamMeta {
            key: stream_key(),
            request_head: vec![1, 2, 3],
            last_activity: Instant::now(),
        }
    }

    #[test]
    fn open_stream_reaps_when_both_halves_are_closed() {
        let (request_reader, mut request_writer) = pipe::pipe(8);
        let (_response_reader, response_writer) = pipe::pipe(8);
        request_writer.finish();

        let mut state = StreamState::Initiator(InitiatorStream {
            meta: stream_meta(),
            control: StreamControl::new(),
            request: OutboundBody::new(Direction::Request, request_reader, 0, true),
            response: InboundBody::new(response_writer, 8),
            accept: InitiatorAccept::Open {
                response_head: Vec::new(),
            },
        });

        if let Some(outbound) = state.outbound_mut(Direction::Request) {
            outbound.closed = true;
        }
        if let Some(inbound) = state.inbound_mut(Direction::Response) {
            inbound.closed = true;
            inbound.pipe.finish();
        }

        assert!(state.can_reap());
    }

    #[test]
    fn rejecting_stream_reaps_once_control_is_idle() {
        let state = StreamState::Responder(ResponderStream {
            meta: stream_meta(),
            control: StreamControl::new(),
            request: InboundBody::new(pipe::pipe(8).1, 8),
            response: ResponderResponse::Rejecting { initial_credit: 8 },
        });
        assert!(state.can_reap());
    }
}
