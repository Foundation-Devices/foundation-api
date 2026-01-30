use std::{
    cell::Cell,
    cmp::Reverse,
    collections::{BinaryHeap, VecDeque},
    future::Future,
    task::Poll,
    time::Instant,
};

use bc_components::{EncapsulationPublicKey, XID};
use dcbor::CBOR;
use futures_lite::future::poll_fn;

use crate::{
    handshake,
    pairing,
    platform::{PlatformFuture, QlPlatform, QlPlatformExt},
    runtime::{InitiatorStage, PeerRecord, PeerSession, Runtime, RuntimeCommand, Token},
    wire::{handshake::HandshakeMessage, pairing::PairingRequest, QlMessage},
    QlError,
};

pub struct RuntimeState {
    peers: Vec<PeerRecord>,
    next_token: Cell<Token>,
    outbound: VecDeque<OutboundMessage>,
    timeouts: BinaryHeap<Reverse<TimeoutEntry>>,
}

impl RuntimeState {
    pub fn new() -> Self {
        Self {
            peers: Vec::new(),
            next_token: Cell::new(Token(0)),
            outbound: VecDeque::new(),
            timeouts: BinaryHeap::new(),
        }
    }

    fn next_token(&self) -> Token {
        let token = self.next_token.get();
        self.next_token.set(token.next());
        token
    }

    fn peer(&self, peer: XID) -> Option<&PeerRecord> {
        self.peers.iter().find(|record| record.peer == peer)
    }

    fn peer_mut(&mut self, peer: XID) -> Option<&mut PeerRecord> {
        self.peers.iter_mut().find(|record| record.peer == peer)
    }

    fn upsert_peer(
        &mut self,
        peer: XID,
        signing_key: bc_components::SigningPublicKey,
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

struct InFlightWrite<'a> {
    peer: XID,
    token: Token,
    future: PlatformFuture<'a, Result<(), QlError>>,
}

struct OutboundMessage {
    peer: XID,
    token: Token,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimeoutKind {
    Outbound { token: Token },
    Handshake { peer: XID, token: Token },
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

impl<P: QlPlatform> Runtime<P> {
    pub async fn run(self) {
        let mut state = RuntimeState::new();
        let mut in_flight: Option<InFlightWrite<'_>> = None;
        loop {
            if in_flight.is_none() {
                in_flight = self.start_next_write(&mut state);
            }
            let step = self.next_step(&state, in_flight.as_mut()).await;
            match step {
                LoopStep::Event(command) => match command {
                    RuntimeCommand::RegisterPeer {
                        peer,
                        signing_key,
                        encapsulation_key,
                    } => {
                        self.handle_register_peer(&mut state, peer, signing_key, encapsulation_key);
                    }
                    RuntimeCommand::Connect { peer } => {
                        self.handle_connect(&mut state, peer);
                    }
                    RuntimeCommand::Incoming(bytes) => {
                        self.handle_incoming(&mut state, bytes);
                    }
                },
                LoopStep::Timeout => {
                    self.handle_timeouts(&mut state);
                }
                LoopStep::WriteDone {
                    peer,
                    token,
                    result,
                } => {
                    in_flight = None;
                    self.handle_write_done(&mut state, peer, token, result);
                }
                LoopStep::Quit => break,
            }
        }
    }

    fn start_next_write<'a>(&'a self, state: &mut RuntimeState) -> Option<InFlightWrite<'a>> {
        let Some(message) = state.outbound.pop_front() else {
            return None;
        };
        Some(InFlightWrite {
            peer: message.peer,
            token: message.token,
            future: self.platform.write_message(message.bytes),
        })
    }

    async fn next_step<'a>(
        &'a self,
        state: &RuntimeState,
        mut in_flight: Option<&mut InFlightWrite<'a>>,
    ) -> LoopStep {
        let recv_future = self.rx.recv();
        futures_lite::pin!(recv_future);

        let mut sleep_future = next_timeout_deadline(state).map(|deadline| {
            let timeout = deadline.saturating_duration_since(Instant::now());
            self.platform.sleep(timeout)
        });

        let step = poll_fn(|cx| {
            if let Some(in_flight) = in_flight.as_mut() {
                if let Poll::Ready(result) = in_flight.future.as_mut().poll(cx) {
                    return Poll::Ready(LoopStep::WriteDone {
                        peer: in_flight.peer,
                        token: in_flight.token,
                        result,
                    });
                }
            }

            if let Some(future) = sleep_future.as_mut() {
                if let std::task::Poll::Ready(()) = future.as_mut().poll(cx) {
                    return std::task::Poll::Ready(LoopStep::Timeout);
                }
            }

            match recv_future.as_mut().poll(cx) {
                std::task::Poll::Ready(Ok(event)) => std::task::Poll::Ready(LoopStep::Event(event)),
                std::task::Poll::Ready(Err(_)) => std::task::Poll::Ready(LoopStep::Quit),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        })
        .await;
        step
    }

    fn handle_connect(&self, state: &mut RuntimeState, peer: XID) {
        let encapsulation_key = match state.peer(peer) {
            Some(entry) => match &entry.session {
                PeerSession::Connected { .. }
                | PeerSession::Initiator { .. }
                | PeerSession::Responder { .. } => {
                    return;
                }
                PeerSession::Disconnected => entry.encapsulation_key.clone(),
            },
            None => return,
        };

        let (hello, session_key) = match handshake::build_hello(
            &self.platform,
            self.platform.xid(),
            peer,
            &encapsulation_key,
        ) {
            Ok(result) => result,
            Err(_) => return,
        };

        let deadline = Instant::now() + self.config.handshake_timeout;
        let token = state.next_token();
        if let Some(entry) = state.peer_mut(peer) {
            entry.session = PeerSession::Initiator {
                handshake_token: token,
                hello: hello.clone(),
                session_key,
                deadline,
                stage: InitiatorStage::WaitingHelloReply,
            };
            self.platform.handle_peer_status(peer, &entry.session);
        }

        let message = QlMessage::Handshake(HandshakeMessage::Hello(hello));
        let bytes = CBOR::from(message).to_cbor_data();
        self.enqueue_handshake_message(state, peer, token, deadline, bytes);
    }

    fn handle_register_peer(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        signing_key: bc_components::SigningPublicKey,
        encapsulation_key: EncapsulationPublicKey,
    ) {
        let entry = state.upsert_peer(peer, signing_key, encapsulation_key);
        if let PeerSession::Disconnected = entry.session {
            self.platform.handle_peer_status(peer, &entry.session);
        }
    }

    fn handle_incoming(&self, state: &mut RuntimeState, bytes: Vec<u8>) {
        let Ok(message) = CBOR::try_from_data(&bytes).and_then(QlMessage::try_from) else {
            return;
        };
        match message {
            QlMessage::Handshake(message) => {
                self.handle_handshake(state, message);
            }
            QlMessage::Pairing(request) => {
                self.handle_pairing(state, request);
            }
        }
    }

    fn handle_handshake(&self, state: &mut RuntimeState, message: HandshakeMessage) {
        match message {
            HandshakeMessage::Hello(hello) => {
                self.handle_hello(state, hello);
            }
            HandshakeMessage::HelloReply(reply) => {
                self.handle_hello_reply(state, reply);
            }
            HandshakeMessage::Confirm(confirm) => {
                self.handle_confirm(state, confirm);
            }
        }
    }

    fn handle_pairing(&self, state: &mut RuntimeState, request: PairingRequest) {
        if request.header.recipient != self.platform.xid() {
            return;
        }
        let payload = match pairing::decrypt_pairing_request(&self.platform, request) {
            Ok(payload) => payload,
            Err(_) => return,
        };
        let peer = XID::new(&payload.signing_pub_key);
        state.upsert_peer(peer, payload.signing_pub_key, payload.encapsulation_pub_key);
        self.handle_connect(state, peer);
    }

    fn handle_hello(&self, state: &mut RuntimeState, hello: crate::wire::handshake::Hello) {
        if hello.header.recipient != self.platform.xid() {
            return;
        }
        let peer = hello.header.sender;
        let action = match state.peer(peer) {
            Some(entry) => match &entry.session {
                PeerSession::Initiator {
                    hello: local_hello, ..
                } => {
                    if peer_hello_wins(local_hello, &hello) {
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
                self.start_responder_handshake(state, peer, hello);
            }
            HelloAction::ResendReply { reply, deadline } => {
                let message = QlMessage::Handshake(HandshakeMessage::HelloReply(reply));
                let bytes = CBOR::from(message).to_cbor_data();
                self.enqueue_outbound(state, peer, bytes, deadline);
            }
            HelloAction::Ignore => {}
        }
    }

    fn handle_hello_reply(
        &self,
        state: &mut RuntimeState,
        reply: crate::wire::handshake::HelloReply,
    ) {
        if reply.header.recipient != self.platform.xid() {
            return;
        }
        let peer = reply.header.sender;
        let (hello, initiator_secret, stage, responder_signing_key) = match state.peer(peer) {
            Some(entry) => match &entry.session {
                PeerSession::Initiator {
                    hello,
                    session_key,
                    stage,
                    ..
                } => (
                    hello.clone(),
                    session_key.clone(),
                    *stage,
                    entry.signing_key.clone(),
                ),
                _ => return,
            },
            None => return,
        };

        if stage != InitiatorStage::WaitingHelloReply {
            return;
        }

        let confirm = match handshake::build_confirm(
            &self.platform,
            &responder_signing_key,
            &hello,
            &reply,
            &initiator_secret,
        ) {
            Ok((confirm, session_key)) => {
                if let Some(entry) = state.peer_mut(peer) {
                    entry.session = PeerSession::Connected { session_key };
                    self.platform.handle_peer_status(peer, &entry.session);
                }
                confirm
            }
            Err(_) => {
                if let Some(entry) = state.peer_mut(peer) {
                    entry.session = PeerSession::Disconnected;
                    self.platform.handle_peer_status(peer, &entry.session);
                }
                return;
            }
        };

        let message = QlMessage::Handshake(HandshakeMessage::Confirm(confirm));
        let bytes = CBOR::from(message).to_cbor_data();
        let deadline = Instant::now() + self.config.handshake_timeout;
        self.enqueue_outbound(state, peer, bytes, deadline);
    }

    fn handle_confirm(&self, state: &mut RuntimeState, confirm: crate::wire::handshake::Confirm) {
        if confirm.header.recipient != self.platform.xid() {
            return;
        }
        let peer = confirm.header.sender;
        let (hello, reply, secrets, initiator_signing_key) = match state.peer(peer) {
            Some(entry) => match &entry.session {
                PeerSession::Responder {
                    hello,
                    reply,
                    secrets,
                    ..
                } => (
                    hello.clone(),
                    reply.clone(),
                    secrets.clone(),
                    entry.signing_key.clone(),
                ),
                _ => return,
            },
            None => return,
        };

        match handshake::finalize_confirm(
            &initiator_signing_key,
            &hello,
            &reply,
            &confirm,
            &secrets,
        ) {
            Ok(session_key) => {
                if let Some(entry) = state.peer_mut(peer) {
                    entry.session = PeerSession::Connected { session_key };
                    self.platform.handle_peer_status(peer, &entry.session);
                }
            }
            Err(_) => {
                if let Some(entry) = state.peer_mut(peer) {
                    entry.session = PeerSession::Disconnected;
                    self.platform.handle_peer_status(peer, &entry.session);
                }
            }
        }
    }

    fn start_responder_handshake(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        hello: crate::wire::handshake::Hello,
    ) {
        let encapsulation_key = match state.peer(peer) {
            Some(entry) => entry.encapsulation_key.clone(),
            None => return,
        };
        let (reply, secrets) = match handshake::respond_hello(
            &self.platform,
            self.platform.xid(),
            &encapsulation_key,
            &hello,
        ) {
            Ok(result) => result,
            Err(_) => {
                if let Some(entry) = state.peer_mut(peer) {
                    entry.session = PeerSession::Disconnected;
                    self.platform.handle_peer_status(peer, &entry.session);
                }
                return;
            }
        };

        let deadline = Instant::now() + self.config.handshake_timeout;
        let token = state.next_token();
        if let Some(entry) = state.peer_mut(peer) {
            entry.session = PeerSession::Responder {
                handshake_token: token,
                hello: hello.clone(),
                reply: reply.clone(),
                secrets,
                deadline,
            };
            self.platform.handle_peer_status(peer, &entry.session);
        }

        let message = QlMessage::Handshake(HandshakeMessage::HelloReply(reply));
        let bytes = CBOR::from(message).to_cbor_data();
        self.enqueue_handshake_message(state, peer, token, deadline, bytes);
    }

    fn enqueue_handshake_message(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        token: Token,
        deadline: Instant,
        bytes: Vec<u8>,
    ) {
        state
            .outbound
            .push_back(OutboundMessage { peer, token, bytes });
        state.timeouts.push(Reverse(TimeoutEntry {
            at: deadline,
            kind: TimeoutKind::Handshake { peer, token },
        }));
        state.timeouts.push(Reverse(TimeoutEntry {
            at: deadline,
            kind: TimeoutKind::Outbound { token },
        }));
    }

    fn enqueue_outbound(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        bytes: Vec<u8>,
        deadline: Instant,
    ) {
        let token = state.next_token();
        state
            .outbound
            .push_back(OutboundMessage { peer, token, bytes });
        state.timeouts.push(Reverse(TimeoutEntry {
            at: deadline,
            kind: TimeoutKind::Outbound { token },
        }));
    }

    fn handle_timeouts(&self, state: &mut RuntimeState) {
        let now = Instant::now();
        while let Some(entry) = state.timeouts.peek() {
            if entry.0.at > now {
                break;
            }
            let entry = state.timeouts.pop().expect("timeout entry just peeked").0;
            match entry.kind {
                TimeoutKind::Outbound { token } => {
                    state.outbound.retain(|message| message.token != token);
                }
                TimeoutKind::Handshake { peer, token } => {
                    let should_disconnect = match state.peer(peer) {
                        Some(entry) => match &entry.session {
                            PeerSession::Initiator {
                                handshake_token, ..
                            }
                            | PeerSession::Responder {
                                handshake_token, ..
                            } => *handshake_token == token,
                            _ => false,
                        },
                        None => false,
                    };
                    if should_disconnect {
                        if let Some(entry) = state.peer_mut(peer) {
                            entry.session = PeerSession::Disconnected;
                            self.platform.handle_peer_status(peer, &entry.session);
                        }
                        state.outbound.retain(|message| message.peer != peer);
                    }
                }
            }
        }
    }

    fn handle_write_done(
        &self,
        state: &mut RuntimeState,
        peer: XID,
        token: Token,
        result: Result<(), QlError>,
    ) {
        match result {
            Ok(()) => {}
            Err(_) => {
                let should_disconnect = match state.peer(peer).map(|entry| &entry.session) {
                    Some(PeerSession::Initiator {
                        handshake_token, ..
                    }) if *handshake_token == token => true,
                    Some(PeerSession::Responder {
                        handshake_token, ..
                    }) if *handshake_token == token => true,
                    _ => false,
                };
                if should_disconnect {
                    if let Some(entry) = state.peer_mut(peer) {
                        entry.session = PeerSession::Disconnected;
                        self.platform.handle_peer_status(peer, &entry.session);
                    }
                    state.outbound.retain(|message| message.peer != peer);
                }
            }
        }
    }
}

enum LoopStep {
    Event(RuntimeCommand),
    Timeout,
    WriteDone {
        peer: XID,
        token: Token,
        result: Result<(), QlError>,
    },
    Quit,
}

enum HelloAction {
    StartResponder,
    ResendReply {
        reply: crate::wire::handshake::HelloReply,
        deadline: Instant,
    },
    Ignore,
}

fn next_timeout_deadline(state: &RuntimeState) -> Option<Instant> {
    state.timeouts.peek().map(|entry| entry.0.at)
}

fn peer_hello_wins(
    local_hello: &crate::wire::handshake::Hello,
    peer_hello: &crate::wire::handshake::Hello,
) -> bool {
    use std::cmp::Ordering;

    match peer_hello.nonce.data().cmp(local_hello.nonce.data()) {
        Ordering::Less => true,
        Ordering::Greater => false,
        Ordering::Equal => {
            peer_hello
                .header
                .sender
                .data()
                .cmp(local_hello.header.sender.data())
                == Ordering::Less
        }
    }
}
