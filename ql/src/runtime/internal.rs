use std::{
    cell::Cell,
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, VecDeque},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use async_channel::{Receiver, Sender};
use bc_components::{MLDSAPublicKey, MLKEMPublicKey, SymmetricKey, XID};
use dcbor::CBOR;

use crate::{
    platform::PlatformFuture,
    runtime::{replay_cache::ReplayCache, RequestConfig},
    wire::{
        handshake::{Hello, HelloReply},
        message::{MessageBody, MessageKind},
    },
    MessageId, Peer, QlError, RouteId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
// Monotonic token for timeout correlation.
pub struct Token(u64);

#[derive(Debug, Clone)]
// Per-peer keepalive timers and ping state.
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
// Registered peer identity and current session.
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
// In-memory registry of known peers.
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
// Session state machine for a peer.
pub enum PeerSession {
    // No active handshake or session.
    Disconnected,
    // Local side initiated the handshake.
    Initiator {
        handshake_token: Token,
        hello: Hello,
        session_key: SymmetricKey,
        deadline: Instant,
        stage: InitiatorStage,
    },
    // Local side is responding to a handshake.
    Responder {
        handshake_token: Token,
        hello: Hello,
        reply: HelloReply,
        secrets: crate::wire::handshake::ResponderSecrets,
        deadline: Instant,
    },
    // Encrypted session is established.
    Connected {
        session_key: SymmetricKey,
        keepalive: KeepAliveState,
    },
}

impl PeerSession {
    #[inline]
    pub fn is_connected(&self) -> bool {
        matches!(self, PeerSession::Connected { .. })
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
// Initiator-side handshake progression.
pub enum InitiatorStage {
    // Waiting for hello reply.
    WaitingHelloReply,
    // Waiting for confirm completion.
    WaitingConfirmAck,
}

// Producer messages for outbound transfer data.
pub(crate) enum OutboundStreamInput {
    // Emit one data chunk.
    Chunk(Vec<u8>),
    // Mark stream end.
    Finish,
}

// Consumer messages for inbound transfer reads.
pub(crate) enum InboundStreamItem {
    // Next received data chunk.
    Chunk(Vec<u8>),
    // Clean stream completion.
    Finished,
    // Terminal stream failure.
    Error(QlError),
}

// Runtime-delivered stream metadata and receiver.
pub(crate) struct InboundStreamDelivery {
    pub peer: XID,
    pub transfer_id: MessageId,
    pub meta: CBOR,
    pub rx: Receiver<InboundStreamItem>,
    pub tx: Sender<RuntimeCommand>,
}

// Last sender frame currently awaiting ack.
pub enum OutboundAwaiting {
    // Open frame with request correlation.
    Open { request_id: MessageId, meta: CBOR },
    // Data frame at a specific sequence.
    Chunk { seq: u32, data: Vec<u8> },
    // Finish frame at a specific sequence.
    Finish { seq: u32 },
    // Cancel frame awaiting cancel-ack.
    Cancel,
}

// Coarse sender-side transfer lifecycle.
pub enum OutboundTransferStage {
    // Opening frame not yet acknowledged.
    Opening,
    // Streaming chunks frame-by-frame.
    Streaming,
    // Finish frame sent, waiting for ack.
    Finishing,
    // Cancellation in progress.
    Cancelling,
}

// Runtime state for one outbound transfer.
pub struct OutboundTransferState {
    pub request_id: MessageId,
    pub peer: XID,
    pub transfer_id: MessageId,
    pub stage: OutboundTransferStage,
    pub next_seq: u32,
    pub open_meta: Option<CBOR>,
    pub chunk_rx: Receiver<OutboundStreamInput>,
    pub awaiting: Option<OutboundAwaiting>,
}

// Runtime state for one inbound transfer.
pub struct InboundTransferState {
    pub expected_seq: u32,
    pub chunk_tx: Sender<InboundStreamItem>,
}

// Commands consumed by the runtime loop.
pub(crate) enum RuntimeCommand {
    // Upsert a peer record.
    RegisterPeer {
        peer: XID,
        signing_key: MLDSAPublicKey,
        encapsulation_key: MLKEMPublicKey,
    },
    // Start handshake with a peer.
    Connect {
        peer: XID,
    },
    // Send unpair and remove peer.
    Unpair {
        peer: XID,
    },
    // Send unary request and await unary response.
    SendRequest {
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
        respond_to: oneshot::Sender<Result<CBOR, QlError>>,
        config: RequestConfig,
    },
    // Send unary request and await streamed response.
    SendStreamRequest {
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
        respond_to: oneshot::Sender<Result<InboundStreamDelivery, QlError>>,
        config: RequestConfig,
    },
    // Send fire-and-forget event.
    SendEvent {
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
    },
    // Send unary response or nack.
    SendResponse {
        id: MessageId,
        recipient: XID,
        payload: CBOR,
        kind: MessageKind,
    },
    // Start sender-side streamed response.
    StartResponseStream {
        request_id: MessageId,
        recipient: XID,
        meta: CBOR,
        chunk_rx: Receiver<OutboundStreamInput>,
    },
    // Prompt immediate outbound transfer polling.
    PollOutboundTransfer {
        recipient: XID,
        transfer_id: MessageId,
    },
    // Cancel sender-side active transfer.
    CancelOutboundTransfer {
        recipient: XID,
        transfer_id: MessageId,
    },
    // Cancel receiver-side active transfer.
    CancelInboundTransfer {
        sender: XID,
        transfer_id: MessageId,
    },
    // Process raw incoming bytes.
    Incoming(Vec<u8>),
}

// Mutable state owned by the runtime loop.
pub struct RuntimeState {
    pub peers: PeerStore,
    pub next_token: Cell<Token>,
    pub outbound: VecDeque<OutboundMessage>,
    pub timeouts: BinaryHeap<Reverse<TimeoutEntry>>,
    pub pending: HashMap<MessageId, PendingEntry>,
    pub pending_stream: HashMap<MessageId, PendingStreamEntry>,
    pub outbound_transfers: HashMap<(XID, MessageId), OutboundTransferState>,
    pub inbound_transfers: HashMap<(XID, MessageId), InboundTransferState>,
    pub next_message_id: Cell<MessageId>,
    pub replay_cache: ReplayCache,
}

impl RuntimeState {
    pub fn new() -> Self {
        Self {
            peers: PeerStore::new(),
            next_token: Cell::new(Token(1)),
            outbound: VecDeque::new(),
            timeouts: BinaryHeap::new(),
            pending: HashMap::new(),
            pending_stream: HashMap::new(),
            outbound_transfers: HashMap::new(),
            inbound_transfers: HashMap::new(),
            next_message_id: Cell::new(MessageId(1)),
            replay_cache: ReplayCache::new(),
        }
    }

    pub fn next_token(&self) -> Token {
        let token = self.next_token.get();
        self.next_token.set(Token(token.0.wrapping_add(1)));
        token
    }

    pub fn next_message_id(&self) -> MessageId {
        let id = self.next_message_id.get();
        self.next_message_id.set(MessageId(id.0.wrapping_add(1)));
        id
    }
}

// Pending unary response waiter.
pub struct PendingEntry {
    pub recipient: XID,
    pub tx: oneshot::Sender<Result<CBOR, QlError>>,
}

// Pending streamed response opener waiter.
pub struct PendingStreamEntry {
    pub recipient: XID,
    pub tx: oneshot::Sender<Result<InboundStreamDelivery, QlError>>,
}

// Currently executing platform write.
pub struct InFlightWrite<'a> {
    pub peer: XID,
    pub token: Token,
    pub message_id: Option<MessageId>,
    pub future: PlatformFuture<'a, Result<(), QlError>>,
}

// Queued payload representation.
pub enum OutboundPayload {
    // Payload already encoded into bytes.
    PreEncoded(Vec<u8>),
    // Payload to encrypt at send time.
    DeferredMessage(MessageBody),
}

// Outbound queue item with timeout token.
pub struct OutboundMessage {
    pub peer: XID,
    pub token: Token,
    pub message_id: Option<MessageId>,
    pub payload: OutboundPayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Runtime timeout categories.
pub enum TimeoutKind {
    // Outbound queue item expired.
    Outbound {
        token: Token,
    },
    // Handshake stage expired.
    Handshake {
        peer: XID,
        token: Token,
    },
    // Request waiting for reply expired.
    Request {
        id: MessageId,
    },
    // Send keepalive ping now.
    KeepAliveSend {
        peer: XID,
        token: Token,
    },
    // Keepalive pong timeout.
    KeepAliveTimeout {
        peer: XID,
        token: Token,
    },
    // Transfer data/open/finish ack timeout.
    TransferAck {
        peer: XID,
        transfer_id: MessageId,
        next_seq: u32,
        attempt: u8,
    },
    // Transfer cancel-ack timeout.
    TransferCancelAck {
        peer: XID,
        transfer_id: MessageId,
        attempt: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
// One scheduled timeout entry.
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

// Outcome of one runtime loop poll cycle.
pub enum LoopStep {
    // Received a runtime command.
    Event(RuntimeCommand),
    // One or more timeouts fired.
    Timeout,
    // In-flight write completed.
    WriteDone {
        peer: XID,
        token: Token,
        message_id: Option<MessageId>,
        result: Result<(), QlError>,
    },
    // Runtime should exit loop.
    Quit,
}

// Decision for inbound hello handling.
pub enum HelloAction {
    // Become responder for this hello.
    StartResponder,
    // Re-send existing hello reply.
    ResendReply {
        reply: HelloReply,
        deadline: Instant,
    },
    // Ignore this hello.
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
