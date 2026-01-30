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
        Self {
            peers: Vec::new(),
        }
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
            return &mut self.peers[index];
        }
        self.peers
            .push(PeerRecord::new(peer, signing_key, encapsulation_key));
        self.peers
            .last_mut()
            .expect("peer record just inserted")
    }
}

impl<P: QlPlatform> Runtime<P> {
    pub async fn run(mut self) {
        let mut state = RuntimeState::new();
        loop {
            let step = self.next_step(&state).await;
            match step {
                LoopStep::Event(command) => match command {
                    RuntimeCommand::SendHello {
                        peer,
                        signing_key,
                        encapsulation_key,
                    } => {
                        self.handle_send_hello(
                            &mut state,
                            peer,
                            signing_key,
                            encapsulation_key,
                        )
                        .await;
                    }
                    RuntimeCommand::Incoming(bytes) => {
                        self.handle_incoming(&mut state, bytes).await;
                    }
                },
                LoopStep::Timeout(peer) => {
                    self.handle_handshake_timeout(&mut state, peer).await;
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
                std::task::Poll::Ready(Ok(event)) => {
                    std::task::Poll::Ready(LoopStep::Event(event))
                }
                std::task::Poll::Ready(Err(_)) => std::task::Poll::Ready(LoopStep::Quit),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        })
        .await
    }

    async fn handle_send_hello(
        &mut self,
        state: &mut RuntimeState,
        peer: XID,
        signing_key: bc_components::SigningPublicKey,
        encapsulation_key: EncapsulationPublicKey,
    ) {
        let (hello, session_key) = match handshake::build_hello(
            &self.platform,
            self.platform.xid(),
            peer,
            &encapsulation_key,
        ) {
            Ok(result) => result,
            Err(_) => return,
        };

        let entry = state.upsert_peer(peer, signing_key.clone(), encapsulation_key.clone());
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

    async fn handle_incoming(&mut self, _state: &mut RuntimeState, bytes: Vec<u8>) {
        let Ok(message) = CBOR::try_from_data(&bytes).and_then(QlMessage::try_from) else {
            return;
        };
        match message {
            QlMessage::Handshake(_) => {
                // TODO: handshake state machine
            }
        }
    }

    async fn handle_handshake_timeout(&mut self, state: &mut RuntimeState, peer: XID) {
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
            PeerSession::Initiator { deadline, .. }
            | PeerSession::Responder { deadline, .. } => Some((record.peer, *deadline)),
            _ => None,
        })
        .min_by_key(|(_, deadline)| *deadline)
}
