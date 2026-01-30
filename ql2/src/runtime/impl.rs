use std::{future::Future, time::Instant};

use bc_components::{EncapsulationPublicKey, XID};
use dcbor::CBOR;
use futures_lite::future::poll_fn;

use crate::{
    handshake,
    platform::{QlPlatform, QlPlatformExt},
    runtime::{InitiatorStage, PeerRecord, PeerSession, Runtime, RuntimeCommand},
    wire::{handshake::HandshakeMessage, QlMessage},
};

pub struct RuntimeState {
    peers: Vec<PeerRecord>,
}

impl RuntimeState {
    pub fn new() -> Self {
        Self { peers: Vec::new() }
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

impl<P: QlPlatform> Runtime<P> {
    pub async fn run(mut self) {
        let mut state = RuntimeState::new();
        loop {
            let step = self.next_step(&state).await;
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
                        self.handle_connect(&mut state, peer).await;
                    }
                    RuntimeCommand::Incoming(bytes) => {
                        self.handle_incoming(&mut state, bytes).await;
                    }
                },
                LoopStep::Timeout(peer) => {
                    self.handle_handshake_timeout(&mut state, peer);
                }
                LoopStep::Quit => break,
            }
        }
    }

    async fn next_step(&mut self, state: &RuntimeState) -> LoopStep {
        let recv_future = self.rx.recv();
        futures_lite::pin!(recv_future);

        let mut sleep_future = next_handshake_deadline(state).map(|(peer, deadline)| {
            let timeout = deadline.saturating_duration_since(Instant::now());
            (peer, self.platform.sleep(timeout))
        });

        poll_fn(|cx| {
            if let Some((peer, future)) = sleep_future.as_mut() {
                if let std::task::Poll::Ready(()) = future.as_mut().poll(cx) {
                    return std::task::Poll::Ready(LoopStep::Timeout(*peer));
                }
            }

            match recv_future.as_mut().poll(cx) {
                std::task::Poll::Ready(Ok(event)) => std::task::Poll::Ready(LoopStep::Event(event)),
                std::task::Poll::Ready(Err(_)) => std::task::Poll::Ready(LoopStep::Quit),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        })
        .await
    }

    async fn handle_connect(&mut self, state: &mut RuntimeState, peer: XID) {
        let Some(entry) = state.peer_mut(peer) else {
            return;
        };
        match entry.session {
            PeerSession::Connected { .. }
            | PeerSession::Initiator { .. }
            | PeerSession::Responder { .. } => {
                return;
            }
            PeerSession::Disconnected => {}
        }

        let encapsulation_key = entry.encapsulation_key.clone();
        let (hello, session_key) = match handshake::build_hello(
            &self.platform,
            self.platform.xid(),
            peer,
            &encapsulation_key,
        ) {
            Ok(result) => result,
            Err(_) => return,
        };

        entry.session = PeerSession::Initiator {
            hello: hello.clone(),
            session_key,
            deadline: Instant::now() + self.config.handshake_timeout,
            stage: InitiatorStage::WaitingHelloReply,
        };
        self.platform.handle_peer_status(peer, &entry.session);

        let message = QlMessage::Handshake(HandshakeMessage::Hello(hello));
        let bytes = CBOR::from(message).to_cbor_data();
        let _ = self.platform.write_message(bytes).await;
    }

    fn handle_register_peer(
        &mut self,
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

    async fn handle_incoming(&mut self, state: &mut RuntimeState, bytes: Vec<u8>) {
        let Ok(message) = CBOR::try_from_data(&bytes).and_then(QlMessage::try_from) else {
            return;
        };
        match message {
            QlMessage::Handshake(message) => {
                self.handle_handshake(state, message).await;
            }
        }
    }

    async fn handle_handshake(&mut self, state: &mut RuntimeState, message: HandshakeMessage) {
        match message {
            HandshakeMessage::Hello(hello) => {
                self.handle_hello(state, hello).await;
            }
            HandshakeMessage::HelloReply(reply) => {
                self.handle_hello_reply(state, reply).await;
            }
            HandshakeMessage::Confirm(confirm) => {
                self.handle_confirm(state, confirm).await;
            }
        }
    }

    async fn handle_hello(
        &mut self,
        state: &mut RuntimeState,
        hello: crate::wire::handshake::Hello,
    ) {
        if hello.header.recipient != self.platform.xid() {
            return;
        }
        let peer = hello.header.sender;
        let Some(entry) = state.peer_mut(peer) else {
            return;
        };

        match &entry.session {
            PeerSession::Initiator {
                hello: local_hello, ..
            } => {
                if peer_hello_wins(local_hello, &hello) {
                    self.start_responder_handshake(entry, hello).await;
                }
            }
            PeerSession::Responder {
                hello: stored,
                reply,
                ..
            } => {
                if stored.nonce == hello.nonce {
                    let message = QlMessage::Handshake(HandshakeMessage::HelloReply(reply.clone()));
                    let bytes = CBOR::from(message).to_cbor_data();
                    let _ = self.platform.write_message(bytes).await;
                } else {
                    self.start_responder_handshake(entry, hello).await;
                }
            }
            PeerSession::Disconnected | PeerSession::Connected { .. } => {
                self.start_responder_handshake(entry, hello).await;
            }
        }
    }

    async fn handle_hello_reply(
        &mut self,
        state: &mut RuntimeState,
        reply: crate::wire::handshake::HelloReply,
    ) {
        if reply.header.recipient != self.platform.xid() {
            return;
        }
        let peer = reply.header.sender;
        let Some(entry) = state.peer_mut(peer) else {
            return;
        };

        let (hello, initiator_secret, stage) = match &entry.session {
            PeerSession::Initiator {
                hello,
                session_key,
                stage,
                ..
            } => (hello.clone(), session_key.clone(), *stage),
            _ => return,
        };

        if stage != InitiatorStage::WaitingHelloReply {
            return;
        }

        let confirm = match handshake::build_confirm(
            &self.platform,
            &entry.signing_key,
            &hello,
            &reply,
            &initiator_secret,
        ) {
            Ok((confirm, session_key)) => {
                entry.session = PeerSession::Connected { session_key };
                self.platform.handle_peer_status(peer, &entry.session);
                confirm
            }
            Err(_) => {
                entry.session = PeerSession::Disconnected;
                self.platform.handle_peer_status(peer, &entry.session);
                return;
            }
        };

        let message = QlMessage::Handshake(HandshakeMessage::Confirm(confirm));
        let bytes = CBOR::from(message).to_cbor_data();
        let _ = self.platform.write_message(bytes).await;
    }

    async fn handle_confirm(
        &mut self,
        state: &mut RuntimeState,
        confirm: crate::wire::handshake::Confirm,
    ) {
        if confirm.header.recipient != self.platform.xid() {
            return;
        }
        let peer = confirm.header.sender;
        let Some(entry) = state.peer_mut(peer) else {
            return;
        };

        let (hello, reply, secrets) = match &entry.session {
            PeerSession::Responder {
                hello,
                reply,
                secrets,
                ..
            } => (hello.clone(), reply.clone(), secrets.clone()),
            _ => return,
        };

        match handshake::finalize_confirm(&entry.signing_key, &hello, &reply, &confirm, &secrets) {
            Ok(session_key) => {
                entry.session = PeerSession::Connected { session_key };
                self.platform.handle_peer_status(peer, &entry.session);
            }
            Err(_) => {
                entry.session = PeerSession::Disconnected;
                self.platform.handle_peer_status(peer, &entry.session);
            }
        }
    }

    async fn start_responder_handshake(
        &mut self,
        entry: &mut PeerRecord,
        hello: crate::wire::handshake::Hello,
    ) {
        let (reply, secrets) = match handshake::respond_hello(
            &self.platform,
            self.platform.xid(),
            &entry.encapsulation_key,
            &hello,
        ) {
            Ok(result) => result,
            Err(_) => {
                entry.session = PeerSession::Disconnected;
                self.platform.handle_peer_status(entry.peer, &entry.session);
                return;
            }
        };

        entry.session = PeerSession::Responder {
            hello: hello.clone(),
            reply: reply.clone(),
            secrets,
            deadline: Instant::now() + self.config.handshake_timeout,
        };
        self.platform.handle_peer_status(entry.peer, &entry.session);

        let message = QlMessage::Handshake(HandshakeMessage::HelloReply(reply));
        let bytes = CBOR::from(message).to_cbor_data();
        let _ = self.platform.write_message(bytes).await;
    }

    fn handle_handshake_timeout(&mut self, state: &mut RuntimeState, peer: XID) {
        if let Some(entry) = state.peer_mut(peer) {
            if matches!(entry.session, PeerSession::Connected { .. }) {
                return;
            }
            let deadline = match &entry.session {
                PeerSession::Initiator { deadline, .. } => Some(*deadline),
                PeerSession::Responder { deadline, .. } => Some(*deadline),
                _ => None,
            };
            if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
                entry.session = PeerSession::Disconnected;
                self.platform.handle_peer_status(peer, &entry.session);
            }
        }
    }
}

enum LoopStep {
    Event(RuntimeCommand),
    Timeout(XID),
    Quit,
}

fn next_handshake_deadline(state: &RuntimeState) -> Option<(XID, Instant)> {
    state
        .peers
        .iter()
        .filter_map(|record| match &record.session {
            PeerSession::Initiator { deadline, .. } | PeerSession::Responder { deadline, .. } => {
                Some((record.peer, *deadline))
            }
            _ => None,
        })
        .min_by_key(|(_, deadline)| *deadline)
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
