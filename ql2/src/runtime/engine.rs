use std::{
    cell::Cell,
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, VecDeque},
    time::Instant,
};

use bc_components::{MLDSAPublicKey, MLKEMPublicKey, SigningPublicKey, SymmetricKey, XID};
use dcbor::CBOR;

use crate::{
    platform::QlCrypto,
    runtime::{
        replay_cache::{ReplayCache, ReplayKey, ReplayNamespace},
        KeepAliveConfig, RuntimeConfig, StreamConfig,
    },
    wire::{
        self,
        handshake::{self, Confirm, HandshakeRecord, Hello, HelloReply, ResponderSecrets},
        heartbeat::{self, HeartbeatBody},
        pair::PairRequestRecord,
        stream::{
            self, Direction, RejectCode, ResetCode, ResetTarget, StreamBody, StreamFrame,
            StreamFrameAccept, StreamFrameCredit, StreamFrameData, StreamFrameFinish,
            StreamFrameOpen, StreamFrameReject, StreamFrameReset,
        },
        unpair::{self, UnpairRecord},
        QlHeader, QlPayload, QlRecord,
    },
    MessageId, PacketId, Peer, QlError, StreamId,
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

impl KeepAliveState {
    pub fn new() -> Self {
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
struct StreamKey {
    stream_id: StreamId,
}

#[derive(Debug)]
struct StreamMeta {
    key: StreamKey,
    request_head: Vec<u8>,
    last_activity: Instant,
}

#[derive(Debug)]
struct PendingPull {
    offset: u64,
    max_len: usize,
}

#[derive(Debug)]
struct OutboundState {
    dir: Direction,
    remote_max_offset: u64,
    sent_offset: u64,
    released_offset: u64,
    final_offset: Option<u64>,
    data_enabled: bool,
    closed: bool,
    pending_pull: Option<PendingPull>,
}

impl OutboundState {
    fn new(dir: Direction, remote_max_offset: u64, data_enabled: bool) -> Self {
        Self {
            dir,
            remote_max_offset,
            sent_offset: 0,
            released_offset: 0,
            final_offset: None,
            data_enabled,
            closed: false,
            pending_pull: None,
        }
    }

    fn can_request_data(&self) -> bool {
        self.data_enabled
            && !self.closed
            && self.pending_pull.is_none()
            && self.sent_offset < self.remote_max_offset
            && self
                .final_offset
                .is_none_or(|final_offset| self.sent_offset < final_offset)
    }
}

#[derive(Debug)]
struct InboundState {
    next_offset: u64,
    max_offset: u64,
    closed: bool,
}

impl InboundState {
    fn new(max_offset: u64) -> Self {
        Self {
            next_offset: 0,
            max_offset,
            closed: false,
        }
    }
}

#[derive(Debug)]
struct OpenWaiter {
    open_id: Option<OpenId>,
    open_timeout_token: Token,
}

#[derive(Debug)]
enum InitiatorAccept {
    Opening(OpenWaiter),
    WaitingAccept(OpenWaiter),
    Open { response_head: Vec<u8> },
}

#[derive(Debug)]
struct InitiatorStream {
    meta: StreamMeta,
    control: StreamControl,
    request: OutboundState,
    response: InboundState,
    accept: InitiatorAccept,
}

#[derive(Debug)]
enum ResponderResponse {
    Pending {
        initial_credit: u64,
    },
    Accepted {
        initial_credit: u64,
        body: OutboundState,
    },
    Rejecting {
        initial_credit: u64,
    },
}

#[derive(Debug)]
struct ResponderStream {
    meta: StreamMeta,
    control: StreamControl,
    request: InboundState,
    response: ResponderResponse,
}

#[derive(Debug)]
enum StreamState {
    Initiator(InitiatorStream),
    Responder(ResponderStream),
}

impl StreamState {
    fn key(&self) -> StreamKey {
        match self {
            Self::Initiator(state) => state.meta.key,
            Self::Responder(state) => state.meta.key,
        }
    }

    fn last_activity_mut(&mut self) -> &mut Instant {
        match self {
            Self::Initiator(state) => &mut state.meta.last_activity,
            Self::Responder(state) => &mut state.meta.last_activity,
        }
    }

    fn control(&self) -> &StreamControl {
        match self {
            Self::Initiator(state) => &state.control,
            Self::Responder(state) => &state.control,
        }
    }

    fn control_mut(&mut self) -> &mut StreamControl {
        match self {
            Self::Initiator(state) => &mut state.control,
            Self::Responder(state) => &mut state.control,
        }
    }

    fn outbound_mut(&mut self, dir: Direction) -> Option<&mut OutboundState> {
        match self {
            Self::Initiator(state) if dir == Direction::Request => Some(&mut state.request),
            Self::Responder(state) if dir == Direction::Response => match &mut state.response {
                ResponderResponse::Accepted { body, .. } => Some(body),
                _ => None,
            },
            _ => None,
        }
    }

    fn inbound_mut(&mut self, dir: Direction) -> Option<&mut InboundState> {
        match self {
            Self::Initiator(state) if dir == Direction::Response => Some(&mut state.response),
            Self::Responder(state) if dir == Direction::Request => Some(&mut state.request),
            _ => None,
        }
    }

    fn open_timeout_token(&self) -> Option<Token> {
        match self {
            Self::Initiator(state) => match &state.accept {
                InitiatorAccept::Opening(waiter) | InitiatorAccept::WaitingAccept(waiter) => {
                    Some(waiter.open_timeout_token)
                }
                InitiatorAccept::Open { .. } => None,
            },
            _ => None,
        }
    }

    fn can_reap(&self) -> bool {
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
                ResponderResponse::Pending { .. } => false,
            },
        }
    }
}

#[derive(Debug)]
struct AwaitingPacket {
    packet_id: PacketId,
    frame: AwaitingFrame,
    attempt: u8,
}

#[derive(Debug, Clone)]
enum AwaitingFrame {
    Control(StreamFrame),
    Data {
        dir: Direction,
        offset: u64,
        len: usize,
    },
}

#[derive(Debug)]
enum SetupFrame {
    Open(StreamFrameOpen),
    Accept(StreamFrameAccept),
    Reject(StreamFrameReject),
}

#[derive(Debug)]
struct PendingFrames {
    setup: Option<SetupFrame>,
    credit: Option<StreamFrameCredit>,
    reset: Option<StreamFrameReset>,
}

impl PendingFrames {
    fn new() -> Self {
        Self {
            setup: None,
            credit: None,
            reset: None,
        }
    }

    fn take_next_control(&mut self, stream_id: StreamId) -> Option<StreamFrame> {
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

    fn set_setup(&mut self, setup: SetupFrame) {
        self.setup = Some(setup);
    }

    fn set_credit(&mut self, frame: StreamFrameCredit) {
        if self.reset.is_none() {
            self.credit = Some(frame);
        }
    }

    fn set_reset(&mut self, dir: ResetTarget, code: ResetCode) {
        self.credit = None;
        self.reset = Some(StreamFrameReset {
            stream_id: StreamId(0),
            dir,
            code,
        });
    }

    fn is_empty(&self) -> bool {
        self.setup.is_none() && self.credit.is_none() && self.reset.is_none()
    }
}

#[derive(Debug)]
struct StreamControl {
    pending: PendingFrames,
    awaiting: Option<AwaitingPacket>,
}

impl StreamControl {
    fn new() -> Self {
        Self {
            pending: PendingFrames::new(),
            awaiting: None,
        }
    }
}

#[derive(Debug)]
enum QueuedPayload {
    PreEncoded(Vec<u8>),
    StreamBody(StreamBody),
}

#[derive(Debug)]
struct QueuedWrite {
    token: Token,
    stream_id: Option<StreamId>,
    packet_id: Option<PacketId>,
    track_ack: bool,
    payload: QueuedPayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimeoutKind {
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
struct TimeoutEntry {
    at: Instant,
    kind: TimeoutKind,
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
enum HelloAction {
    StartResponder,
    ResendReply {
        reply: HelloReply,
        deadline: Instant,
    },
    Ignore,
}

pub struct Engine {
    pub config: RuntimeConfig,
    pub state: EngineState,
    streams: HashMap<StreamId, StreamState>,
}

pub struct EngineState {
    pub peer: Option<PeerRecord>,
    replay_cache: ReplayCache,

    next_token: Cell<u64>,
    next_id: Cell<u64>,
    outbound: VecDeque<QueuedWrite>,
    timeouts: BinaryHeap<Reverse<TimeoutEntry>>,
    write_in_flight: Option<Token>,
}

impl EngineState {
    fn new(peer: Option<Peer>) -> Self {
        Self {
            peer: peer
                .map(|peer| PeerRecord::new(peer.peer, peer.signing_key, peer.encapsulation_key)),
            replay_cache: ReplayCache::new(),
            next_token: Cell::new(1),
            next_id: Cell::new(1),
            outbound: VecDeque::new(),
            timeouts: BinaryHeap::new(),
            write_in_flight: None,
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.timeouts.peek().map(|entry| entry.0.at)
    }

    fn next_token(&self) -> Token {
        let token = self.next_token.get();
        self.next_token.set(token.wrapping_add(1));
        Token(token)
    }

    fn next_packet_id(&self) -> PacketId {
        let id = self.next_id.get();
        self.next_id.set(id.wrapping_add(1));
        PacketId(id)
    }

    fn next_stream_id(&self) -> StreamId {
        let id = self.next_id.get();
        self.next_id.set(id.wrapping_add(1));
        StreamId(id)
    }

    fn enqueue_handshake_message(
        &mut self,
        _config: &RuntimeConfig,
        token: Token,
        deadline: Instant,
        bytes: Vec<u8>,
    ) {
        self.outbound.push_back(QueuedWrite {
            token,
            stream_id: None,
            packet_id: None,
            track_ack: false,
            payload: QueuedPayload::PreEncoded(bytes),
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

    fn enqueue_stream_body(
        &mut self,
        config: &RuntimeConfig,
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
            payload: QueuedPayload::StreamBody(body),
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

    fn enqueue_control_frame(
        &mut self,
        config: &RuntimeConfig,
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
        let valid_until = wire::now_secs().saturating_add(config.packet_expiration.as_secs());
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

    fn enqueue_data_frame(
        &mut self,
        config: &RuntimeConfig,
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
        let valid_until = wire::now_secs().saturating_add(config.packet_expiration.as_secs());
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

impl Engine {
    pub fn new(config: RuntimeConfig, peer: Option<Peer>) -> Self {
        Self {
            config,
            state: EngineState::new(peer),
            streams: HashMap::new(),
        }
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.state.next_deadline()
    }

    pub fn run_tick(
        &mut self,
        now: Instant,
        input: EngineInput,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        match input {
            EngineInput::BindPeer(peer) => self.handle_bind_peer(peer, emit),
            EngineInput::Pair => self.handle_pair_local(now, crypto),
            EngineInput::Connect => self.handle_connect(now, crypto, emit),
            EngineInput::Unpair => self.handle_unpair_local(now, crypto, emit),
            EngineInput::OpenStream {
                open_id,
                request_head,
                config,
            } => self.handle_open_stream(now, open_id, request_head, config, emit),
            EngineInput::AcceptStream {
                stream_id,
                response_head,
            } => self.handle_accept_stream(now, stream_id, response_head),
            EngineInput::RejectStream { stream_id, code } => {
                self.handle_reject_stream(now, stream_id, code)
            }
            EngineInput::OutboundData {
                stream_id,
                dir,
                offset,
                bytes,
            } => self.handle_outbound_data(stream_id, dir, offset, bytes),
            EngineInput::OutboundFinished {
                stream_id,
                dir,
                final_offset,
            } => self.handle_outbound_finished(stream_id, dir, final_offset),
            EngineInput::InboundConsumed {
                stream_id,
                dir,
                amount,
            } => self.handle_inbound_consumed(now, stream_id, dir, amount),
            EngineInput::ResetOutbound {
                stream_id,
                dir,
                code,
            } => self.handle_reset_outbound(now, stream_id, dir, code),
            EngineInput::ResetInbound {
                stream_id,
                dir,
                code,
            } => self.handle_reset_inbound(now, stream_id, dir, code),
            EngineInput::PendingAcceptDropped { stream_id } => {
                self.handle_pending_accept_dropped(stream_id, emit)
            }
            EngineInput::ResponderDropped { stream_id } => {
                self.handle_responder_dropped(now, stream_id)
            }
            EngineInput::Incoming(bytes) => self.handle_incoming(now, bytes, crypto, emit),
            EngineInput::WriteCompleted {
                token,
                tracked,
                result,
            } => self.handle_write_done(now, token, tracked, result, emit),
            EngineInput::TimerExpired => self.handle_timeouts(now, crypto, emit),
        }

        self.drive_streams(now, emit);
        self.maybe_start_next_write(crypto, emit);
        emit(EngineOutput::SetTimer(self.state.next_deadline()));
    }

    fn emit_peer_status(&self, emit: &mut impl OutputFn) {
        if let Some(peer) = self.state.peer.as_ref() {
            emit(EngineOutput::PeerStatusChanged {
                peer: peer.peer,
                session: peer.session.clone(),
            });
        }
    }

    fn bind_peer_record(&mut self, peer: Peer, emit: &mut impl OutputFn) {
        self.reset_runtime(QlError::Cancelled, emit);
        self.state.peer = Some(PeerRecord::new(
            peer.peer,
            peer.signing_key,
            peer.encapsulation_key,
        ));
        self.emit_peer_status(emit);
        if let Some(peer) = self.state.peer.as_ref() {
            emit(EngineOutput::PersistPeer(peer.snapshot()));
        }
    }

    fn reset_runtime(&mut self, error: QlError, emit: &mut impl OutputFn) {
        let stream_ids: Vec<_> = self.streams.keys().copied().collect();
        for stream_id in stream_ids {
            self.fail_stream(stream_id, error.clone(), emit);
        }
        self.state.outbound.clear();
        self.state.timeouts.clear();
        self.state.write_in_flight = None;
        if let Some(peer) = self.state.peer.as_ref().map(|peer| peer.peer) {
            self.state.replay_cache.clear_peer(peer);
        }
    }

    fn handle_bind_peer(&mut self, peer: Peer, emit: &mut impl OutputFn) {
        if let Some(existing) = self.state.peer.as_ref() {
            emit(EngineOutput::PeerStatusChanged {
                peer: existing.peer,
                session: PeerSession::Disconnected,
            });
        }
        self.bind_peer_record(peer, emit);
    }

    fn handle_pair_local(&mut self, now: Instant, crypto: &impl QlCrypto) {
        let Some(peer) = self.state.peer.as_ref() else {
            return;
        };
        let Ok(record) = wire::pair::build_pair_request(
            crypto,
            peer.peer,
            &peer.encapsulation_key,
            MessageId(self.state.next_packet_id().0),
            self.config.packet_expiration,
        ) else {
            return;
        };
        let token = self.state.next_token();
        self.enqueue_handshake_message(
            token,
            now + self.config.packet_expiration,
            CBOR::from(record).to_cbor_data(),
        );
    }

    fn handle_connect(&mut self, now: Instant, crypto: &impl QlCrypto, emit: &mut impl OutputFn) {
        let Some(peer_record) = self.state.peer.as_ref() else {
            return;
        };
        let peer = peer_record.peer;
        let (hello, session_key) = match &peer_record.session {
            PeerSession::Connected { .. }
            | PeerSession::Initiator { .. }
            | PeerSession::Responder { .. } => {
                return;
            }
            PeerSession::Disconnected => {
                match handshake::build_hello(
                    crypto,
                    crypto.xid(),
                    peer,
                    &peer_record.encapsulation_key,
                ) {
                    Ok(result) => result,
                    Err(_) => return,
                }
            }
        };

        let deadline = now + self.config.handshake_timeout;
        let token = self.state.next_token();
        if let Some(entry) = self.state.peer.as_mut() {
            entry.session = PeerSession::Initiator {
                handshake_token: token,
                hello: hello.clone(),
                session_key,
                deadline,
                stage: InitiatorStage::WaitingHelloReply,
            };
        }
        self.emit_peer_status(emit);

        let record = QlRecord {
            header: QlHeader {
                sender: crypto.xid(),
                recipient: peer,
            },
            payload: QlPayload::Handshake(HandshakeRecord::Hello(hello)),
        };
        self.enqueue_handshake_message(token, deadline, CBOR::from(record).to_cbor_data());
    }

    fn handle_unpair_local(
        &mut self,
        now: Instant,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        let Some(peer) = self.state.peer.as_ref().map(|peer| peer.peer) else {
            return;
        };
        let record = unpair::build_unpair_record(
            crypto,
            QlHeader {
                sender: crypto.xid(),
                recipient: peer,
            },
            MessageId(self.state.next_packet_id().0),
            wire::now_secs().saturating_add(self.config.packet_expiration.as_secs()),
        );
        self.unpair_peer(emit);
        let token = self.state.next_token();
        self.enqueue_handshake_message(
            token,
            now + self.config.packet_expiration,
            CBOR::from(record).to_cbor_data(),
        );
    }

    fn handle_open_stream(
        &mut self,
        now: Instant,
        open_id: OpenId,
        request_head: Vec<u8>,
        config: StreamConfig,
        emit: &mut impl OutputFn,
    ) {
        let Some(entry) = self.state.peer.as_ref() else {
            emit(EngineOutput::OpenFailed {
                open_id,
                stream_id: StreamId(0),
                error: QlError::NoPeerBound,
            });
            return;
        };
        if !entry.session.is_connected() {
            emit(EngineOutput::OpenFailed {
                open_id,
                stream_id: StreamId(0),
                error: QlError::MissingSession,
            });
            return;
        }

        let stream_id = self.state.next_stream_id();
        let open_timeout = config
            .open_timeout
            .unwrap_or(self.config.default_open_timeout);
        let token = self.state.next_token();
        let frame = StreamFrameOpen {
            stream_id,
            request_head: request_head.clone(),
            response_max_offset: self.config.initial_credit,
        };
        let stream = StreamState::Initiator(InitiatorStream {
            meta: StreamMeta {
                key: StreamKey { stream_id },
                request_head,
                last_activity: now,
            },
            control: StreamControl {
                pending: PendingFrames {
                    setup: Some(SetupFrame::Open(frame)),
                    credit: None,
                    reset: None,
                },
                awaiting: None,
            },
            request: OutboundState::new(Direction::Request, self.config.initial_credit, true),
            response: InboundState::new(self.config.initial_credit),
            accept: InitiatorAccept::Opening(OpenWaiter {
                open_id: Some(open_id),
                open_timeout_token: token,
            }),
        });
        self.streams.insert(stream_id, stream);
        self.state.timeouts.push(Reverse(TimeoutEntry {
            at: now + open_timeout,
            kind: TimeoutKind::StreamOpen { stream_id, token },
        }));
        emit(EngineOutput::OpenStarted { open_id, stream_id });
    }

    fn handle_accept_stream(&mut self, now: Instant, stream_id: StreamId, response_head: Vec<u8>) {
        let Some(StreamState::Responder(stream)) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let ResponderResponse::Pending { initial_credit } = stream.response else {
            return;
        };
        stream
            .control
            .pending
            .set_setup(SetupFrame::Accept(StreamFrameAccept {
                stream_id,
                response_head,
                request_max_offset: self.config.initial_credit,
            }));
        stream.request.max_offset = self.config.initial_credit;
        stream.response = ResponderResponse::Accepted {
            initial_credit,
            body: OutboundState::new(Direction::Response, initial_credit, false),
        };
        stream.meta.last_activity = now;
    }

    fn handle_reject_stream(&mut self, now: Instant, stream_id: StreamId, code: RejectCode) {
        let Some(StreamState::Responder(stream)) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let ResponderResponse::Pending { initial_credit } = stream.response else {
            return;
        };
        stream
            .control
            .pending
            .set_setup(SetupFrame::Reject(StreamFrameReject { stream_id, code }));
        stream.response = ResponderResponse::Rejecting { initial_credit };
        stream.meta.last_activity = now;
    }

    fn handle_outbound_data(
        &mut self,
        stream_id: StreamId,
        dir: Direction,
        offset: u64,
        bytes: Vec<u8>,
    ) {
        if bytes.is_empty() {
            return;
        }
        let (streams, state) = (&mut self.streams, &mut self.state);
        let Some(stream) = streams.get_mut(&stream_id) else {
            return;
        };
        let Some(outbound) = stream.outbound_mut(dir) else {
            return;
        };
        let Some(pull) = outbound.pending_pull.take() else {
            return;
        };
        if pull.offset != offset {
            outbound.pending_pull = Some(pull);
            return;
        }
        if bytes.len() > pull.max_len {
            outbound.pending_pull = Some(pull);
            return;
        }
        outbound.sent_offset = outbound.sent_offset.saturating_add(bytes.len() as u64);
        let key = stream.key();
        let control = stream.control_mut();
        state.enqueue_data_frame(&self.config, key, control, dir, offset, bytes, 0);
    }

    fn handle_outbound_finished(&mut self, stream_id: StreamId, dir: Direction, final_offset: u64) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let Some(outbound) = stream.outbound_mut(dir) else {
            return;
        };
        if final_offset < outbound.sent_offset {
            return;
        }
        outbound.final_offset = Some(final_offset);
    }

    fn handle_inbound_consumed(
        &mut self,
        now: Instant,
        stream_id: StreamId,
        dir: Direction,
        amount: u64,
    ) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let Some(inbound) = stream.inbound_mut(dir) else {
            return;
        };
        if inbound.closed {
            return;
        }
        inbound.max_offset = inbound.max_offset.saturating_add(amount);
        Self::queue_credit(stream, dir);
        *stream.last_activity_mut() = now;
    }

    fn handle_reset_outbound(
        &mut self,
        now: Instant,
        stream_id: StreamId,
        dir: Direction,
        code: ResetCode,
    ) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let Some(outbound) = stream.outbound_mut(dir) else {
            return;
        };
        if outbound.closed {
            return;
        }
        outbound.closed = true;
        outbound.pending_pull = None;
        stream
            .control_mut()
            .pending
            .set_reset(reset_target_for_dir(dir), code);
        *stream.last_activity_mut() = now;
    }

    fn handle_reset_inbound(
        &mut self,
        now: Instant,
        stream_id: StreamId,
        dir: Direction,
        code: ResetCode,
    ) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let Some(inbound) = stream.inbound_mut(dir) else {
            return;
        };
        if inbound.closed {
            return;
        }
        inbound.closed = true;
        stream
            .control_mut()
            .pending
            .set_reset(reset_target_for_dir(dir), code);
        *stream.last_activity_mut() = now;
    }

    fn handle_responder_dropped(&mut self, now: Instant, stream_id: StreamId) {
        self.handle_reject_stream(now, stream_id, RejectCode::Unhandled);
    }

    fn handle_pending_accept_dropped(&mut self, stream_id: StreamId, emit: &mut impl OutputFn) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        if let StreamState::Initiator(stream) = stream {
            match &mut stream.accept {
                InitiatorAccept::Opening(waiter) | InitiatorAccept::WaitingAccept(waiter) => {
                    waiter.open_id = None;
                }
                InitiatorAccept::Open { .. } => {}
            }
        }
        self.maybe_reap_stream(stream_id, emit);
    }

    fn handle_incoming(
        &mut self,
        now: Instant,
        bytes: Vec<u8>,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        let Ok(record) = CBOR::try_from_data(&bytes).and_then(QlRecord::try_from) else {
            return;
        };
        let QlRecord { header, payload } = record;
        if header.recipient != crypto.xid() {
            return;
        }
        if !matches!(payload, QlPayload::Pair(_)) {
            let Some(peer) = self.state.peer.as_ref().map(|peer| peer.peer) else {
                return;
            };
            if header.sender != peer {
                return;
            }
        }
        match payload {
            QlPayload::Handshake(message) => {
                self.handle_handshake(now, header, message, crypto, emit)
            }
            QlPayload::Stream(encrypted) => self.handle_stream(now, header, encrypted, emit),
            QlPayload::Heartbeat(encrypted) => {
                self.handle_heartbeat(now, header, encrypted, crypto, emit)
            }
            QlPayload::Pair(request) => self.handle_pairing(now, header, request, crypto, emit),
            QlPayload::Unpair(record) => self.handle_unpair(header, record, emit),
        }
    }

    fn handle_handshake(
        &mut self,
        now: Instant,
        header: QlHeader,
        message: HandshakeRecord,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        match message {
            HandshakeRecord::Hello(hello) => self.handle_hello(now, header, hello, crypto, emit),
            HandshakeRecord::HelloReply(reply) => {
                self.handle_hello_reply(now, header, reply, crypto, emit)
            }
            HandshakeRecord::Confirm(confirm) => {
                self.handle_confirm(now, header, confirm, crypto, emit)
            }
        }
    }

    fn handle_pairing(
        &mut self,
        now: Instant,
        header: QlHeader,
        request: PairRequestRecord,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        let payload = match wire::pair::decrypt_pair_request(crypto, &header, request) {
            Ok(payload) => payload,
            Err(_) => return,
        };
        let peer = XID::new(SigningPublicKey::MLDSA(payload.signing_pub_key.clone()));
        if let Some(existing) = self.state.peer.as_ref() {
            if existing.peer != peer
                || existing.signing_key != payload.signing_pub_key
                || existing.encapsulation_key != payload.encapsulation_pub_key
            {
                return;
            }
        } else {
            self.bind_peer_record(
                Peer {
                    peer,
                    signing_key: payload.signing_pub_key,
                    encapsulation_key: payload.encapsulation_pub_key,
                },
                emit,
            );
        }
        self.handle_connect(now, crypto, emit);
    }

    fn handle_unpair(&mut self, header: QlHeader, record: UnpairRecord, emit: &mut impl OutputFn) {
        let peer = header.sender;
        {
            let Some(peer_record) = self.state.peer.as_ref() else {
                return;
            };
            if unpair::verify_unpair_record(&header, &record, &peer_record.signing_key).is_err() {
                return;
            }
        }
        let replay_key =
            ReplayKey::new(peer, ReplayNamespace::Peer, MessageId(record.message_id.0));
        if self
            .state
            .replay_cache
            .check_and_store_valid_until(replay_key, record.valid_until)
        {
            return;
        }
        self.unpair_peer(emit);
    }

    fn handle_heartbeat(
        &mut self,
        now: Instant,
        header: QlHeader,
        encrypted: bc_components::EncryptedMessage,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        let should_reply = {
            let Some(peer_record) = self.state.peer.as_ref() else {
                return;
            };
            let PeerSession::Connected {
                session_key,
                keepalive,
            } = &peer_record.session
            else {
                return;
            };
            if heartbeat::decrypt_heartbeat(&header, &encrypted, session_key).is_err() {
                return;
            }
            !keepalive.pending
        };
        self.record_activity(now);
        if should_reply {
            self.send_heartbeat_message(now, crypto);
        }
        self.emit_peer_status(emit);
    }

    fn handle_stream(
        &mut self,
        now: Instant,
        header: QlHeader,
        encrypted: bc_components::EncryptedMessage,
        emit: &mut impl OutputFn,
    ) {
        let peer = header.sender;
        let body = {
            let Some(peer_record) = self.state.peer.as_ref() else {
                return;
            };
            let PeerSession::Connected { session_key, .. } = &peer_record.session else {
                return;
            };
            match stream::decrypt_stream(&header, &encrypted, session_key) {
                Ok(body) => body,
                Err(_) => return,
            }
        };

        if let Some(ack) = body.packet_ack {
            self.process_packet_ack(ack.packet_id, emit);
        }

        let Some(frame) = body.frame else {
            return;
        };

        let replay_key =
            ReplayKey::new(peer, ReplayNamespace::Transfer, MessageId(body.packet_id.0));
        if self
            .state
            .replay_cache
            .check_and_store_valid_until(replay_key, body.valid_until)
        {
            return;
        }

        self.record_activity(now);
        self.record_stream_activity(stream_id_from_frame(&frame), now);
        self.send_packet_ack(body.packet_id);

        match frame {
            StreamFrame::Open(frame) => self.handle_stream_open(now, frame, emit),
            StreamFrame::Accept(frame) => self.handle_stream_accept_from_peer(now, frame, emit),
            StreamFrame::Reject(frame) => self.handle_stream_reject_from_peer(frame, emit),
            StreamFrame::Data(frame) => self.handle_stream_data(now, frame, emit),
            StreamFrame::Credit(frame) => self.handle_stream_credit(now, frame, emit),
            StreamFrame::Finish(frame) => self.handle_stream_finish(now, frame, emit),
            StreamFrame::Reset(frame) => self.handle_stream_reset(now, frame, emit),
        }
    }

    fn handle_stream_open(
        &mut self,
        now: Instant,
        frame: StreamFrameOpen,
        emit: &mut impl OutputFn,
    ) {
        let StreamFrameOpen {
            stream_id,
            request_head,
            response_max_offset,
        } = frame;
        if let Some(stream) = self.streams.get(&stream_id) {
            if self.stream_matches_open(stream, &request_head, response_max_offset) {
                return;
            }
            self.send_ephemeral_reset(stream_id, ResetTarget::Both, ResetCode::Protocol);
            return;
        }

        let stream = StreamState::Responder(ResponderStream {
            meta: StreamMeta {
                key: StreamKey { stream_id },
                request_head: request_head.clone(),
                last_activity: now,
            },
            control: StreamControl::new(),
            request: InboundState::new(0),
            response: ResponderResponse::Pending {
                initial_credit: response_max_offset,
            },
        });
        self.streams.insert(stream_id, stream);
        emit(EngineOutput::InboundStreamOpened {
            stream_id,
            request_head,
        });
    }

    fn handle_stream_accept_from_peer(
        &mut self,
        now: Instant,
        frame: StreamFrameAccept,
        emit: &mut impl OutputFn,
    ) {
        let StreamFrameAccept {
            stream_id,
            response_head,
            request_max_offset,
        } = frame;
        let mut protocol = false;
        {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return;
            };
            match stream {
                StreamState::Initiator(stream) => match &mut stream.accept {
                    InitiatorAccept::Opening(waiter) => {
                        if matches!(
                            stream
                                .control
                                .awaiting
                                .as_ref()
                                .map(|awaiting| &awaiting.frame),
                            Some(AwaitingFrame::Control(StreamFrame::Open(_)))
                        ) {
                            stream.control.awaiting = None;
                        }
                        stream.request.remote_max_offset = request_max_offset;
                        stream.request.data_enabled = true;
                        if let Some(open_id) = waiter.open_id.take() {
                            emit(EngineOutput::OpenAccepted {
                                open_id,
                                stream_id,
                                response_head: response_head.clone(),
                            });
                        } else {
                            stream.response.closed = true;
                            stream
                                .control
                                .pending
                                .set_reset(ResetTarget::Response, ResetCode::Cancelled);
                        }
                        stream.accept = InitiatorAccept::Open { response_head };
                        stream.meta.last_activity = now;
                    }
                    InitiatorAccept::WaitingAccept(waiter) => {
                        stream.request.remote_max_offset = request_max_offset;
                        stream.request.data_enabled = true;
                        if let Some(open_id) = waiter.open_id.take() {
                            emit(EngineOutput::OpenAccepted {
                                open_id,
                                stream_id,
                                response_head: response_head.clone(),
                            });
                        } else {
                            stream.response.closed = true;
                            stream
                                .control
                                .pending
                                .set_reset(ResetTarget::Response, ResetCode::Cancelled);
                        }
                        stream.accept = InitiatorAccept::Open { response_head };
                        stream.meta.last_activity = now;
                    }
                    InitiatorAccept::Open {
                        response_head: stored,
                    } => {
                        if *stored != response_head
                            || stream.request.remote_max_offset != request_max_offset
                        {
                            protocol = true;
                        }
                    }
                },
                _ => protocol = true,
            }
        }

        if protocol {
            self.send_ephemeral_reset(stream_id, ResetTarget::Both, ResetCode::Protocol);
        }
    }

    fn handle_stream_reject_from_peer(
        &mut self,
        frame: StreamFrameReject,
        emit: &mut impl OutputFn,
    ) {
        let StreamFrameReject { stream_id, code } = frame;
        let mut protocol = false;
        let mut remove_after = false;
        {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return;
            };
            match stream {
                StreamState::Initiator(stream) => match &mut stream.accept {
                    InitiatorAccept::Opening(waiter) | InitiatorAccept::WaitingAccept(waiter) => {
                        if let Some(open_id) = waiter.open_id.take() {
                            emit(EngineOutput::OpenFailed {
                                open_id,
                                stream_id,
                                error: QlError::StreamRejected { code },
                            });
                        }
                        emit(EngineOutput::OutboundClosed {
                            stream_id,
                            dir: Direction::Request,
                        });
                        emit(EngineOutput::InboundFailed {
                            stream_id,
                            dir: Direction::Response,
                            error: QlError::StreamRejected { code },
                        });
                        stream.request.closed = true;
                        stream.response.closed = true;
                        remove_after = true;
                    }
                    InitiatorAccept::Open { .. } => protocol = true,
                },
                _ => protocol = true,
            }
        }
        if remove_after {
            self.streams.remove(&stream_id);
            emit(EngineOutput::StreamReaped { stream_id });
        }
        if protocol {
            self.send_ephemeral_reset(stream_id, ResetTarget::Both, ResetCode::Protocol);
        }
    }

    fn handle_stream_data(
        &mut self,
        now: Instant,
        frame: StreamFrameData,
        emit: &mut impl OutputFn,
    ) {
        let StreamFrameData {
            stream_id,
            dir,
            offset,
            bytes,
        } = frame;
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        Self::note_setup_seen_from_remote(stream);
        if dir == Direction::Response
            && matches!(
                stream,
                StreamState::Initiator(InitiatorStream {
                    accept: InitiatorAccept::Opening(_) | InitiatorAccept::WaitingAccept(_),
                    ..
                })
            )
        {
            Self::queue_protocol_reset(stream, emit);
            *stream.last_activity_mut() = now;
            return;
        }
        let Some(inbound) = stream.inbound_mut(dir) else {
            Self::queue_protocol_reset(stream, emit);
            return;
        };
        if inbound.closed {
            Self::queue_protocol_reset(stream, emit);
        } else if offset < inbound.next_offset {
            Self::queue_credit(stream, dir);
        } else {
            let end = offset.saturating_add(bytes.len() as u64);
            if offset != inbound.next_offset || end > inbound.max_offset {
                Self::queue_protocol_reset(stream, emit);
            } else {
                inbound.next_offset = end;
                emit(EngineOutput::InboundData {
                    stream_id,
                    dir,
                    bytes,
                });
                Self::queue_credit(stream, dir);
            }
        }
        *stream.last_activity_mut() = now;
    }

    fn handle_stream_credit(
        &mut self,
        now: Instant,
        frame: StreamFrameCredit,
        emit: &mut impl OutputFn,
    ) {
        let StreamFrameCredit {
            stream_id,
            dir,
            recv_offset,
            max_offset,
        } = frame;
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        Self::note_setup_seen_from_remote(stream);
        let Some(outbound) = stream.outbound_mut(dir) else {
            Self::queue_protocol_reset(stream, emit);
            return;
        };
        let released_offset = outbound.released_offset;
        let sent_offset = outbound.sent_offset;
        if recv_offset < released_offset || recv_offset > sent_offset || max_offset < recv_offset {
            Self::queue_protocol_reset(stream, emit);
        } else {
            outbound.released_offset = recv_offset;
            outbound.remote_max_offset = outbound.remote_max_offset.max(max_offset);
            emit(EngineOutput::ReleaseOutboundThrough {
                stream_id,
                dir,
                recv_offset,
            });
            if matches!(
                stream.control().awaiting.as_ref().map(|awaiting| &awaiting.frame),
                Some(AwaitingFrame::Data { offset, len, .. })
                    if recv_offset >= offset.saturating_add(*len as u64)
            ) {
                stream.control_mut().awaiting = None;
            }
        }
        *stream.last_activity_mut() = now;
    }

    fn handle_stream_finish(
        &mut self,
        now: Instant,
        frame: StreamFrameFinish,
        emit: &mut impl OutputFn,
    ) {
        let StreamFrameFinish { stream_id, dir } = frame;
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        Self::note_setup_seen_from_remote(stream);
        let Some(inbound) = stream.inbound_mut(dir) else {
            Self::queue_protocol_reset(stream, emit);
            return;
        };
        if !inbound.closed {
            inbound.closed = true;
            emit(EngineOutput::InboundFinished { stream_id, dir });
        }
        *stream.last_activity_mut() = now;
        self.maybe_reap_stream(stream_id, emit);
    }

    fn handle_stream_reset(
        &mut self,
        now: Instant,
        frame: StreamFrameReset,
        emit: &mut impl OutputFn,
    ) {
        let StreamFrameReset {
            stream_id,
            dir,
            code,
        } = frame;
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        Self::note_setup_seen_from_remote(stream);
        Self::apply_remote_reset(stream, dir, code, emit);
        *stream.last_activity_mut() = now;
        self.maybe_reap_stream(stream_id, emit);
    }

    fn process_packet_ack(&mut self, packet_id: PacketId, emit: &mut impl OutputFn) {
        let key = self.streams.iter().find_map(|(key, stream)| {
            stream
                .control()
                .awaiting
                .as_ref()
                .is_some_and(|awaiting| awaiting.packet_id == packet_id)
                .then_some(*key)
        });
        let Some(key) = key else {
            return;
        };
        let Some(stream) = self.streams.get_mut(&key) else {
            return;
        };
        let Some(awaiting) = stream.control_mut().awaiting.take() else {
            return;
        };

        let mut reap = false;
        match awaiting.frame {
            AwaitingFrame::Control(StreamFrame::Open(_)) => {
                if let StreamState::Initiator(stream) = stream {
                    if let InitiatorAccept::Opening(waiter) = &stream.accept {
                        stream.accept = InitiatorAccept::WaitingAccept(OpenWaiter {
                            open_id: waiter.open_id,
                            open_timeout_token: waiter.open_timeout_token,
                        });
                    }
                }
            }
            AwaitingFrame::Control(StreamFrame::Accept(_)) => {
                if let StreamState::Responder(stream) = stream {
                    if let ResponderResponse::Accepted { body, .. } = &mut stream.response {
                        body.data_enabled = true;
                    }
                }
            }
            AwaitingFrame::Control(StreamFrame::Reject(_)) => {
                reap = true;
            }
            AwaitingFrame::Control(StreamFrame::Finish(StreamFrameFinish { dir, .. })) => {
                if let Some(outbound) = stream.outbound_mut(dir) {
                    outbound.closed = true;
                    emit(EngineOutput::OutboundClosed {
                        stream_id: key,
                        dir,
                    });
                }
            }
            AwaitingFrame::Control(StreamFrame::Reset(StreamFrameReset { dir, code, .. })) => {
                for outbound_dir in [Direction::Request, Direction::Response] {
                    let affects_outbound = matches!(
                        (dir, outbound_dir),
                        (ResetTarget::Request, Direction::Request)
                            | (ResetTarget::Response, Direction::Response)
                            | (ResetTarget::Both, _)
                    );
                    if affects_outbound {
                        if let Some(outbound) = stream.outbound_mut(outbound_dir) {
                            outbound.closed = true;
                            emit(EngineOutput::OutboundFailed {
                                stream_id: key,
                                dir: outbound_dir,
                                error: QlError::StreamReset {
                                    dir: outbound_dir,
                                    code,
                                },
                            });
                        }
                    }
                }
            }
            AwaitingFrame::Control(StreamFrame::Data(_) | StreamFrame::Credit(_)) => {}
            AwaitingFrame::Data { .. } => {}
        }

        if reap {
            self.maybe_reap_stream(key, emit);
        }
    }

    fn drive_streams(&mut self, now: Instant, emit: &mut impl OutputFn) {
        let keys: Vec<_> = self.streams.keys().copied().collect();
        for stream_id in keys {
            self.drive_stream(now, stream_id, emit);
        }
    }

    fn drive_stream(&mut self, _now: Instant, stream_id: StreamId, emit: &mut impl OutputFn) {
        let (streams, state) = (&mut self.streams, &mut self.state);
        let Some(stream) = streams.get_mut(&stream_id) else {
            return;
        };
        match stream {
            StreamState::Initiator(stream) => {
                let action = Self::plan_drive_outbound(
                    &self.config,
                    stream.meta.key,
                    &mut stream.control,
                    Some(&mut stream.request),
                    emit,
                );
                if let Some(frame) = action {
                    state.enqueue_control_frame(
                        &self.config,
                        stream.meta.key,
                        &mut stream.control,
                        frame,
                        0,
                    );
                }
            }
            StreamState::Responder(stream) => {
                let key = stream.meta.key;
                match &mut stream.response {
                    ResponderResponse::Accepted { body, .. } => {
                        let action = Self::plan_drive_outbound(
                            &self.config,
                            key,
                            &mut stream.control,
                            Some(body),
                            emit,
                        );
                        if let Some(frame) = action {
                            state.enqueue_control_frame(
                                &self.config,
                                key,
                                &mut stream.control,
                                frame,
                                0,
                            );
                        }
                    }
                    _ => {
                        let action = Self::plan_drive_outbound(
                            &self.config,
                            key,
                            &mut stream.control,
                            None,
                            emit,
                        );
                        if let Some(frame) = action {
                            state.enqueue_control_frame(
                                &self.config,
                                key,
                                &mut stream.control,
                                frame,
                                0,
                            );
                        }
                    }
                }
            }
        }
    }

    fn plan_drive_outbound(
        config: &RuntimeConfig,
        key: StreamKey,
        control: &mut StreamControl,
        outbound: Option<&mut OutboundState>,
        emit: &mut impl OutputFn,
    ) -> Option<StreamFrame> {
        let stream_id = key.stream_id;
        if control.awaiting.is_some() {
            return None;
        }
        if let Some(frame) = control.pending.take_next_control(stream_id) {
            return Some(frame);
        }
        let Some(outbound) = outbound else {
            return None;
        };
        if outbound.can_request_data() {
            let max_len = (outbound.remote_max_offset - outbound.sent_offset)
                .min(config.max_payload_bytes as u64) as usize;
            if max_len > 0 {
                outbound.pending_pull = Some(PendingPull {
                    offset: outbound.sent_offset,
                    max_len,
                });
                emit(EngineOutput::NeedOutboundData {
                    stream_id,
                    dir: outbound.dir,
                    offset: outbound.sent_offset,
                    max_len,
                });
            }
            return None;
        }
        if outbound.data_enabled
            && !outbound.closed
            && outbound.pending_pull.is_none()
            && outbound
                .final_offset
                .is_some_and(|final_offset| final_offset == outbound.sent_offset)
        {
            outbound.closed = true;
            return Some(StreamFrame::Finish(StreamFrameFinish {
                stream_id,
                dir: outbound.dir,
            }));
        }
        None
    }

    fn send_control_frame(
        &mut self,
        key: StreamKey,
        control: &mut StreamControl,
        frame: StreamFrame,
        attempt: u8,
    ) {
        let packet_id = self.state.next_packet_id();
        control.awaiting = Some(AwaitingPacket {
            packet_id,
            frame: AwaitingFrame::Control(frame.clone()),
            attempt,
        });
        let valid_until = wire::now_secs().saturating_add(self.config.packet_expiration.as_secs());
        self.enqueue_stream_body(
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

    fn send_data_frame(
        &mut self,
        key: StreamKey,
        control: &mut StreamControl,
        dir: Direction,
        offset: u64,
        bytes: Vec<u8>,
        attempt: u8,
    ) {
        let packet_id = self.state.next_packet_id();
        control.awaiting = Some(AwaitingPacket {
            packet_id,
            frame: AwaitingFrame::Data {
                dir,
                offset,
                len: bytes.len(),
            },
            attempt,
        });
        let valid_until = wire::now_secs().saturating_add(self.config.packet_expiration.as_secs());
        self.enqueue_stream_body(
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

    fn queue_credit(stream: &mut StreamState, dir: Direction) {
        let stream_id = stream.key().stream_id;
        let (recv_offset, max_offset) = {
            let Some(inbound) = stream.inbound_mut(dir) else {
                return;
            };
            (inbound.next_offset, inbound.max_offset)
        };
        stream.control_mut().pending.set_credit(StreamFrameCredit {
            stream_id,
            dir,
            recv_offset,
            max_offset,
        });
    }

    fn queue_protocol_reset(stream: &mut StreamState, emit: &mut impl OutputFn) {
        let stream_id = stream.key().stream_id;
        stream
            .control_mut()
            .pending
            .set_reset(ResetTarget::Both, ResetCode::Protocol);
        for dir in [Direction::Request, Direction::Response] {
            if let Some(outbound) = stream.outbound_mut(dir) {
                outbound.closed = true;
                outbound.pending_pull = None;
                emit(EngineOutput::OutboundFailed {
                    stream_id,
                    dir,
                    error: QlError::StreamProtocol,
                });
            }
            if let Some(inbound) = stream.inbound_mut(dir) {
                if !inbound.closed {
                    inbound.closed = true;
                    emit(EngineOutput::InboundFailed {
                        stream_id,
                        dir,
                        error: QlError::StreamProtocol,
                    });
                }
            }
        }
        if let StreamState::Initiator(stream) = stream {
            match &mut stream.accept {
                InitiatorAccept::Opening(waiter) | InitiatorAccept::WaitingAccept(waiter) => {
                    if let Some(open_id) = waiter.open_id.take() {
                        emit(EngineOutput::OpenFailed {
                            open_id,
                            stream_id,
                            error: QlError::StreamProtocol,
                        });
                    }
                }
                InitiatorAccept::Open { .. } => {}
            }
        }
    }

    fn note_setup_seen_from_remote(stream: &mut StreamState) {
        if let StreamState::Responder(stream) = stream {
            if matches!(
                stream
                    .control
                    .awaiting
                    .as_ref()
                    .map(|awaiting| &awaiting.frame),
                Some(AwaitingFrame::Control(StreamFrame::Accept(_)))
            ) {
                stream.control.awaiting = None;
                if let ResponderResponse::Accepted { body, .. } = &mut stream.response {
                    body.data_enabled = true;
                }
            }
            if matches!(
                stream
                    .control
                    .awaiting
                    .as_ref()
                    .map(|awaiting| &awaiting.frame),
                Some(AwaitingFrame::Control(StreamFrame::Reject(_)))
            ) {
                stream.control.awaiting = None;
            }
        }
    }

    fn apply_remote_reset(
        stream: &mut StreamState,
        dir: ResetTarget,
        code: ResetCode,
        emit: &mut impl OutputFn,
    ) {
        let stream_id = stream.key().stream_id;
        let request_error = QlError::StreamReset {
            dir: Direction::Request,
            code,
        };
        let response_error = QlError::StreamReset {
            dir: Direction::Response,
            code,
        };

        if matches!(dir, ResetTarget::Request | ResetTarget::Both) {
            if let Some(inbound) = stream.inbound_mut(Direction::Request) {
                if !inbound.closed {
                    inbound.closed = true;
                    emit(EngineOutput::InboundFailed {
                        stream_id,
                        dir: Direction::Request,
                        error: request_error.clone(),
                    });
                }
            }
            if let Some(outbound) = stream.outbound_mut(Direction::Request) {
                outbound.closed = true;
                outbound.pending_pull = None;
                emit(EngineOutput::OutboundFailed {
                    stream_id,
                    dir: Direction::Request,
                    error: request_error.clone(),
                });
            }
        }
        if matches!(dir, ResetTarget::Response | ResetTarget::Both) {
            if let Some(inbound) = stream.inbound_mut(Direction::Response) {
                if !inbound.closed {
                    inbound.closed = true;
                    emit(EngineOutput::InboundFailed {
                        stream_id,
                        dir: Direction::Response,
                        error: response_error.clone(),
                    });
                }
            }
            if let Some(outbound) = stream.outbound_mut(Direction::Response) {
                outbound.closed = true;
                outbound.pending_pull = None;
                emit(EngineOutput::OutboundFailed {
                    stream_id,
                    dir: Direction::Response,
                    error: response_error.clone(),
                });
            }
        }

        if let StreamState::Initiator(stream) = stream {
            match &mut stream.accept {
                InitiatorAccept::Opening(waiter) | InitiatorAccept::WaitingAccept(waiter) => {
                    if let Some(open_id) = waiter.open_id.take() {
                        emit(EngineOutput::OpenFailed {
                            open_id,
                            stream_id,
                            error: match dir {
                                ResetTarget::Request => request_error,
                                _ => response_error,
                            },
                        });
                    }
                }
                InitiatorAccept::Open { .. } => {}
            }
        }
    }

    fn maybe_reap_stream(&mut self, stream_id: StreamId, emit: &mut impl OutputFn) {
        if self
            .streams
            .get(&stream_id)
            .is_some_and(StreamState::can_reap)
        {
            self.streams.remove(&stream_id);
            emit(EngineOutput::StreamReaped { stream_id });
        }
    }

    fn stream_matches_open(
        &self,
        stream: &StreamState,
        request_head: &[u8],
        response_max_offset: u64,
    ) -> bool {
        match stream {
            StreamState::Responder(state) => match &state.response {
                ResponderResponse::Pending { initial_credit }
                | ResponderResponse::Accepted { initial_credit, .. }
                | ResponderResponse::Rejecting { initial_credit } => {
                    state.meta.request_head == request_head
                        && *initial_credit == response_max_offset
                }
            },
            _ => false,
        }
    }

    fn send_packet_ack(&mut self, acked_packet: PacketId) {
        let packet_id = self.state.next_packet_id();
        let valid_until = wire::now_secs().saturating_add(self.config.packet_expiration.as_secs());
        self.enqueue_stream_body(
            None,
            None,
            false,
            true,
            StreamBody {
                packet_id,
                valid_until,
                packet_ack: Some(stream::PacketAck {
                    packet_id: acked_packet,
                }),
                frame: None,
            },
        );
    }

    fn send_ephemeral_reset(&mut self, stream_id: StreamId, dir: ResetTarget, code: ResetCode) {
        let packet_id = self.state.next_packet_id();
        let valid_until = wire::now_secs().saturating_add(self.config.packet_expiration.as_secs());
        self.enqueue_stream_body(
            None,
            None,
            false,
            true,
            StreamBody {
                packet_id,
                valid_until,
                packet_ack: None,
                frame: Some(StreamFrame::Reset(StreamFrameReset {
                    stream_id,
                    dir,
                    code,
                })),
            },
        );
    }

    fn enqueue_handshake_message(&mut self, token: Token, deadline: Instant, bytes: Vec<u8>) {
        self.state
            .enqueue_handshake_message(&self.config, token, deadline, bytes);
    }

    fn enqueue_stream_body(
        &mut self,
        stream_id: Option<StreamId>,
        packet_id: Option<PacketId>,
        track_ack: bool,
        priority: bool,
        body: StreamBody,
    ) {
        self.state.enqueue_stream_body(
            &self.config,
            stream_id,
            packet_id,
            track_ack,
            priority,
            body,
        );
    }

    fn handle_hello(
        &mut self,
        now: Instant,
        header: QlHeader,
        hello: Hello,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        let peer = header.sender;
        let action = match self.state.peer.as_ref() {
            Some(entry) => match &entry.session {
                PeerSession::Initiator {
                    hello: local_hello, ..
                } => {
                    if peer_hello_wins(local_hello, crypto.xid(), &hello, peer) {
                        HelloAction::StartResponder
                    } else {
                        HelloAction::Ignore
                    }
                }
                PeerSession::Responder {
                    hello: stored,
                    reply,
                    deadline,
                    ..
                } => {
                    if stored.nonce == hello.nonce {
                        HelloAction::ResendReply {
                            reply: reply.clone(),
                            deadline: *deadline,
                        }
                    } else {
                        HelloAction::StartResponder
                    }
                }
                PeerSession::Disconnected | PeerSession::Connected { .. } => {
                    HelloAction::StartResponder
                }
            },
            None => return,
        };

        match action {
            HelloAction::StartResponder => {
                self.start_responder_handshake(now, peer, hello, crypto, emit)
            }
            HelloAction::ResendReply { reply, deadline } => {
                let record = QlRecord {
                    header: QlHeader {
                        sender: crypto.xid(),
                        recipient: peer,
                    },
                    payload: QlPayload::Handshake(HandshakeRecord::HelloReply(reply)),
                };
                let token = self.state.next_token();
                self.enqueue_handshake_message(token, deadline, CBOR::from(record).to_cbor_data());
            }
            HelloAction::Ignore => {}
        }
    }

    fn handle_hello_reply(
        &mut self,
        now: Instant,
        header: QlHeader,
        reply: HelloReply,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        let peer = header.sender;
        let token = self.state.next_token();
        let deadline = now + self.config.handshake_timeout;
        let confirm = match {
            let Some(peer_record) = self.state.peer.as_ref() else {
                return;
            };
            let PeerSession::Initiator {
                hello,
                session_key,
                stage,
                ..
            } = &peer_record.session
            else {
                return;
            };
            if *stage != InitiatorStage::WaitingHelloReply {
                return;
            }
            handshake::build_confirm(
                crypto,
                crypto.xid(),
                peer,
                &peer_record.signing_key,
                hello,
                &reply,
                session_key,
            )
            .map(|(confirm, session_key)| (hello.clone(), confirm, session_key))
        } {
            Ok((hello, confirm, session_key)) => {
                if let Some(entry) = self.state.peer.as_mut() {
                    entry.session = PeerSession::Initiator {
                        handshake_token: token,
                        hello,
                        session_key,
                        deadline,
                        stage: InitiatorStage::SendingConfirm,
                    };
                }
                confirm
            }
            Err(_) => {
                if let Some(entry) = self.state.peer.as_mut() {
                    entry.session = PeerSession::Disconnected;
                }
                self.emit_peer_status(emit);
                return;
            }
        };

        let record = QlRecord {
            header: QlHeader {
                sender: crypto.xid(),
                recipient: peer,
            },
            payload: QlPayload::Handshake(HandshakeRecord::Confirm(confirm)),
        };
        self.enqueue_handshake_message(token, deadline, CBOR::from(record).to_cbor_data());
    }

    fn handle_confirm(
        &mut self,
        now: Instant,
        header: QlHeader,
        confirm: Confirm,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        let peer = header.sender;
        let Some(peer_record) = self.state.peer.as_ref() else {
            return;
        };
        let PeerSession::Responder {
            hello,
            reply,
            secrets,
            ..
        } = &peer_record.session
        else {
            return;
        };

        match handshake::finalize_confirm(
            peer,
            crypto.xid(),
            &peer_record.signing_key,
            hello,
            reply,
            &confirm,
            secrets,
        ) {
            Ok(session_key) => {
                if let Some(entry) = self.state.peer.as_mut() {
                    entry.session = PeerSession::Connected {
                        session_key,
                        keepalive: KeepAliveState::new(),
                    };
                }
                self.record_activity(now);
                self.emit_peer_status(emit);
            }
            Err(_) => {
                if let Some(entry) = self.state.peer.as_mut() {
                    entry.session = PeerSession::Disconnected;
                }
                self.emit_peer_status(emit);
            }
        }
    }

    fn start_responder_handshake(
        &mut self,
        now: Instant,
        peer: XID,
        hello: Hello,
        crypto: &impl QlCrypto,
        emit: &mut impl OutputFn,
    ) {
        let (reply, secrets) = match {
            let Some(peer_record) = self.state.peer.as_ref() else {
                return;
            };
            handshake::respond_hello(
                crypto,
                peer,
                crypto.xid(),
                &peer_record.encapsulation_key,
                &hello,
            )
        } {
            Ok(result) => result,
            Err(_) => {
                if let Some(entry) = self.state.peer.as_mut() {
                    entry.session = PeerSession::Disconnected;
                }
                self.emit_peer_status(emit);
                return;
            }
        };

        let deadline = now + self.config.handshake_timeout;
        let token = self.state.next_token();
        if let Some(entry) = self.state.peer.as_mut() {
            entry.session = PeerSession::Responder {
                handshake_token: token,
                hello,
                reply: reply.clone(),
                secrets,
                deadline,
            };
        }
        self.emit_peer_status(emit);

        let record = QlRecord {
            header: QlHeader {
                sender: crypto.xid(),
                recipient: peer,
            },
            payload: QlPayload::Handshake(HandshakeRecord::HelloReply(reply)),
        };
        self.enqueue_handshake_message(token, deadline, CBOR::from(record).to_cbor_data());
    }

    fn send_heartbeat_message(&mut self, now: Instant, crypto: &impl QlCrypto) {
        let Some(peer) = self.state.peer.as_ref().map(|peer| peer.peer) else {
            return;
        };
        let message_id = MessageId(self.state.next_packet_id().0);
        let token = self.state.next_token();
        let deadline = now + self.config.packet_expiration;
        let message = {
            let Some(peer_record) = self.state.peer.as_ref() else {
                return;
            };
            let PeerSession::Connected { session_key, .. } = &peer_record.session else {
                return;
            };
            heartbeat::encrypt_heartbeat(
                QlHeader {
                    sender: crypto.xid(),
                    recipient: peer,
                },
                session_key,
                HeartbeatBody {
                    message_id,
                    valid_until: wire::now_secs()
                        .saturating_add(self.config.packet_expiration.as_secs()),
                },
            )
        };
        self.enqueue_handshake_message(token, deadline, CBOR::from(message).to_cbor_data());
    }

    fn keep_alive_config(&self) -> Option<KeepAliveConfig> {
        self.config
            .keep_alive
            .filter(|config| !config.interval.is_zero() && !config.timeout.is_zero())
    }

    fn record_activity(&mut self, now: Instant) {
        let Some(config) = self.keep_alive_config() else {
            return;
        };
        let token = self.state.next_token();
        let Some(entry) = self.state.peer.as_mut() else {
            return;
        };
        let PeerSession::Connected { keepalive, .. } = &mut entry.session else {
            return;
        };
        keepalive.last_activity = Some(now);
        keepalive.pending = false;
        keepalive.token = token;
        self.state.timeouts.push(Reverse(TimeoutEntry {
            at: now + config.interval,
            kind: TimeoutKind::KeepAliveSend { token },
        }));
    }

    fn record_stream_activity(&mut self, stream_id: StreamId, now: Instant) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            *stream.last_activity_mut() = now;
        }
    }

    fn drop_outbound(&mut self, emit: &mut impl OutputFn) {
        let stream_ids: Vec<_> = self
            .state
            .outbound
            .iter()
            .filter_map(|message| message.stream_id)
            .collect();
        self.state.outbound.clear();
        for stream_id in stream_ids {
            self.fail_stream(stream_id, QlError::SendFailed, emit);
        }
    }

    fn abort_streams(&mut self, error: QlError, emit: &mut impl OutputFn) {
        let keys: Vec<_> = self.streams.keys().copied().collect();
        for stream_id in keys {
            self.fail_stream(stream_id, error.clone(), emit);
        }
    }

    fn fail_stream(&mut self, stream_id: StreamId, error: QlError, emit: &mut impl OutputFn) {
        let Some(stream) = self.streams.remove(&stream_id) else {
            return;
        };
        match stream {
            StreamState::Initiator(stream) => {
                match stream.accept {
                    InitiatorAccept::Opening(waiter) | InitiatorAccept::WaitingAccept(waiter) => {
                        if let Some(open_id) = waiter.open_id {
                            emit(EngineOutput::OpenFailed {
                                open_id,
                                stream_id,
                                error: error.clone(),
                            });
                        }
                    }
                    InitiatorAccept::Open { .. } => {}
                }
                emit(EngineOutput::OutboundFailed {
                    stream_id,
                    dir: Direction::Request,
                    error: error.clone(),
                });
                emit(EngineOutput::InboundFailed {
                    stream_id,
                    dir: Direction::Response,
                    error,
                });
            }
            StreamState::Responder(stream) => {
                emit(EngineOutput::InboundFailed {
                    stream_id,
                    dir: Direction::Request,
                    error: error.clone(),
                });
                if matches!(stream.response, ResponderResponse::Accepted { .. }) {
                    emit(EngineOutput::OutboundFailed {
                        stream_id,
                        dir: Direction::Response,
                        error,
                    });
                }
            }
        }
        emit(EngineOutput::StreamReaped { stream_id });
    }

    fn unpair_peer(&mut self, emit: &mut impl OutputFn) {
        let Some(peer) = self.state.peer.as_ref().map(|peer| peer.peer) else {
            return;
        };
        self.drop_outbound(emit);
        self.abort_streams(QlError::SendFailed, emit);
        self.state.replay_cache.clear_peer(peer);
        self.state.peer = None;
        emit(EngineOutput::PeerStatusChanged {
            peer,
            session: PeerSession::Disconnected,
        });
        emit(EngineOutput::ClearPeer);
    }

    fn handle_timeouts(&mut self, now: Instant, crypto: &impl QlCrypto, emit: &mut impl OutputFn) {
        loop {
            let Some(entry) = self
                .state
                .timeouts
                .peek_mut()
                .filter(|entry| entry.0.at <= now)
            else {
                break;
            };
            let entry = std::collections::binary_heap::PeekMut::pop(entry).0;
            match entry.kind {
                TimeoutKind::Outbound { token } => {
                    let mut timed_out_stream = None;
                    self.state.outbound.retain(|message| {
                        if message.token == token {
                            timed_out_stream = message.stream_id;
                            false
                        } else {
                            true
                        }
                    });
                    if let Some(stream_id) = timed_out_stream {
                        self.fail_stream(stream_id, QlError::SendFailed, emit);
                    }
                }
                TimeoutKind::Handshake { token } => {
                    let Some(entry) = self.state.peer.as_ref() else {
                        continue;
                    };
                    let should_disconnect = matches!(
                        &entry.session,
                        PeerSession::Initiator { handshake_token, .. } | PeerSession::Responder { handshake_token, .. }
                            if *handshake_token == token
                    );
                    if should_disconnect {
                        if let Some(entry) = self.state.peer.as_mut() {
                            entry.session = PeerSession::Disconnected;
                        }
                        self.emit_peer_status(emit);
                        self.drop_outbound(emit);
                        self.abort_streams(QlError::SendFailed, emit);
                    }
                }
                TimeoutKind::KeepAliveSend { token } => {
                    let Some(config) = self.keep_alive_config() else {
                        continue;
                    };
                    let should_send = {
                        let Some(entry) = self.state.peer.as_ref() else {
                            continue;
                        };
                        let PeerSession::Connected { keepalive, .. } = &entry.session else {
                            continue;
                        };
                        keepalive.token == token && !keepalive.pending
                    };
                    if should_send {
                        self.send_heartbeat_message(now, crypto);
                    }
                    if let Some(entry) = self.state.peer.as_mut() {
                        if let PeerSession::Connected { keepalive, .. } = &mut entry.session {
                            if keepalive.token == token {
                                keepalive.pending = true;
                            }
                        }
                    }
                    self.state.timeouts.push(Reverse(TimeoutEntry {
                        at: now + config.timeout,
                        kind: TimeoutKind::KeepAliveTimeout { token },
                    }));
                }
                TimeoutKind::KeepAliveTimeout { token } => {
                    let Some(entry) = self.state.peer.as_ref() else {
                        continue;
                    };
                    let should_disconnect = matches!(&entry.session, PeerSession::Connected { keepalive, .. } if keepalive.token == token && keepalive.pending);
                    if should_disconnect {
                        if let Some(entry) = self.state.peer.as_mut() {
                            entry.session = PeerSession::Disconnected;
                        }
                        self.emit_peer_status(emit);
                        self.drop_outbound(emit);
                        self.abort_streams(QlError::SendFailed, emit);
                    }
                }
                TimeoutKind::StreamOpen { stream_id, token } => {
                    let should_fail = self
                        .streams
                        .get(&stream_id)
                        .and_then(StreamState::open_timeout_token)
                        .is_some_and(|stream_token| stream_token == token);
                    if should_fail {
                        self.fail_stream(stream_id, QlError::Timeout, emit);
                    }
                }
                TimeoutKind::StreamPacket {
                    stream_id,
                    packet_id,
                    attempt,
                } => {
                    let mut timed_out = false;
                    let mut retransmit_control = None;
                    let mut retransmit_data = None;
                    {
                        let Some(stream) = self.streams.get_mut(&stream_id) else {
                            continue;
                        };
                        let Some(retransmit) =
                            stream.control().awaiting.as_ref().and_then(|awaiting| {
                                if awaiting.packet_id != packet_id || awaiting.attempt != attempt {
                                    return None;
                                }
                                Some(match &awaiting.frame {
                                    AwaitingFrame::Control(frame) => {
                                        EitherRetransmit::Control(frame.clone())
                                    }
                                    AwaitingFrame::Data { dir, offset, len } => {
                                        EitherRetransmit::Data {
                                            dir: *dir,
                                            offset: *offset,
                                            len: *len,
                                        }
                                    }
                                })
                            })
                        else {
                            continue;
                        };

                        if attempt >= self.config.stream_retry_limit {
                            timed_out = true;
                        } else {
                            match retransmit {
                                EitherRetransmit::Control(frame) => {
                                    retransmit_control = Some(frame)
                                }
                                EitherRetransmit::Data { dir, offset, len } => {
                                    retransmit_data = Some((dir, offset, len))
                                }
                            }
                        }
                    }
                    if timed_out {
                        self.fail_stream(stream_id, QlError::Timeout, emit);
                    } else if let Some(frame) = retransmit_control {
                        let (streams, state) = (&mut self.streams, &mut self.state);
                        if let Some(stream) = streams.get_mut(&stream_id) {
                            let key = stream.key();
                            state.enqueue_control_frame(
                                &self.config,
                                key,
                                stream.control_mut(),
                                frame,
                                attempt.saturating_add(1),
                            );
                        }
                    } else if let Some((dir, offset, len)) = retransmit_data {
                        if let Some(stream) = self.streams.get_mut(&stream_id) {
                            if let Some(outbound) = stream.outbound_mut(dir) {
                                outbound.pending_pull = Some(PendingPull {
                                    offset,
                                    max_len: len,
                                });
                                emit(EngineOutput::NeedOutboundData {
                                    stream_id,
                                    dir,
                                    offset,
                                    max_len: len,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn handle_write_done(
        &mut self,
        now: Instant,
        token: Token,
        tracked: Option<TrackedWrite>,
        result: Result<(), QlError>,
        emit: &mut impl OutputFn,
    ) {
        if self.state.write_in_flight == Some(token) {
            self.state.write_in_flight = None;
        }
        if let Err(error) = result {
            if let Some(tracked) = tracked {
                self.fail_stream(tracked.stream_id, error.clone(), emit);
            }
            let should_disconnect = matches!(self.state.peer.as_ref().map(|entry| &entry.session),
                Some(PeerSession::Initiator { handshake_token, .. }) if *handshake_token == token)
                || matches!(self.state.peer.as_ref().map(|entry| &entry.session),
                Some(PeerSession::Responder { handshake_token, .. }) if *handshake_token == token);
            if should_disconnect {
                if let Some(entry) = self.state.peer.as_mut() {
                    entry.session = PeerSession::Disconnected;
                }
                self.emit_peer_status(emit);
                self.drop_outbound(emit);
                self.abort_streams(error, emit);
            }
            return;
        }

        let connected = self
            .state
            .peer
            .as_ref()
            .and_then(|entry| match &entry.session {
                PeerSession::Initiator {
                    session_key,
                    handshake_token,
                    stage: InitiatorStage::SendingConfirm,
                    ..
                } if *handshake_token == token => Some(session_key.clone()),
                _ => None,
            });
        if let Some(session_key) = connected {
            if let Some(entry) = self.state.peer.as_mut() {
                entry.session = PeerSession::Connected {
                    session_key,
                    keepalive: KeepAliveState::new(),
                };
            }
            self.emit_peer_status(emit);
            self.record_activity(now);
        }

        if let Some(tracked) = tracked {
            let attempt = self
                .streams
                .get(&tracked.stream_id)
                .and_then(|stream| stream.control().awaiting.as_ref())
                .and_then(|awaiting| {
                    (awaiting.packet_id == tracked.packet_id).then_some(awaiting.attempt)
                })
                .unwrap_or(0);
            self.state.timeouts.push(Reverse(TimeoutEntry {
                at: now + self.config.packet_ack_timeout,
                kind: TimeoutKind::StreamPacket {
                    stream_id: tracked.stream_id,
                    packet_id: tracked.packet_id,
                    attempt,
                },
            }));
        }
    }

    fn maybe_start_next_write(&mut self, crypto: &impl QlCrypto, emit: &mut impl OutputFn) {
        if self.state.write_in_flight.is_some() {
            return;
        }
        while let Some(message) = self.state.outbound.pop_front() {
            let bytes = match message.payload {
                QueuedPayload::PreEncoded(bytes) => bytes,
                QueuedPayload::StreamBody(body) => {
                    let Some(peer) = self.state.peer.as_ref() else {
                        if let Some(stream_id) = message.stream_id {
                            self.fail_stream(stream_id, QlError::SendFailed, emit);
                        }
                        continue;
                    };
                    let Some(session_key) = peer.session.session_key() else {
                        if let Some(stream_id) = message.stream_id {
                            self.fail_stream(stream_id, QlError::SendFailed, emit);
                        }
                        continue;
                    };
                    let record = stream::encrypt_stream(
                        QlHeader {
                            sender: crypto.xid(),
                            recipient: peer.peer,
                        },
                        session_key,
                        body,
                    );
                    CBOR::from(record).to_cbor_data()
                }
            };

            let tracked = if message.track_ack {
                message
                    .stream_id
                    .zip(message.packet_id)
                    .map(|(stream_id, packet_id)| TrackedWrite {
                        stream_id,
                        packet_id,
                    })
            } else {
                None
            };
            self.state.write_in_flight = Some(message.token);
            emit(EngineOutput::WriteMessage {
                token: message.token,
                tracked,
                bytes,
            });
            break;
        }
    }
}

enum EitherRetransmit {
    Control(StreamFrame),
    Data {
        dir: Direction,
        offset: u64,
        len: usize,
    },
}

fn peer_hello_wins(
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

fn stream_id_from_frame(frame: &StreamFrame) -> StreamId {
    match frame {
        StreamFrame::Open(frame) => frame.stream_id,
        StreamFrame::Accept(frame) => frame.stream_id,
        StreamFrame::Reject(frame) => frame.stream_id,
        StreamFrame::Data(frame) => frame.stream_id,
        StreamFrame::Credit(frame) => frame.stream_id,
        StreamFrame::Finish(frame) => frame.stream_id,
        StreamFrame::Reset(frame) => frame.stream_id,
    }
}

fn reset_target_for_dir(dir: Direction) -> ResetTarget {
    match dir {
        Direction::Request => ResetTarget::Request,
        Direction::Response => ResetTarget::Response,
    }
}
