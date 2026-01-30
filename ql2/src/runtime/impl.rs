use std::{collections::HashMap, future::Future, time::Instant};

use bc_components::{EncapsulationPublicKey, XID};
use dcbor::CBOR;
use futures_lite::future::poll_fn;

use crate::{
    handshake,
    platform::{PeerStatus, QlPlatform},
    runtime::{PeerRecord, Runtime, RuntimeCommand},
    wire::{handshake::HandshakeMessage, QlMessage},
};

pub struct RuntimeState {
    peers: HashMap<XID, PeerRecord>,
}

impl RuntimeState {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
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
            self.local_xid,
            peer,
            &encapsulation_key,
        ) {
            Ok(result) => result,
            Err(_) => return,
        };

        let entry = state.peers.entry(peer).or_insert_with(|| {
            PeerRecord::new(signing_key.clone(), encapsulation_key.clone())
        });
        entry.pending_hello = Some(hello.clone());
        entry.status = PeerStatus::Connecting;
        entry.session_key = Some(session_key);
        entry.handshake_deadline = Some(Instant::now() + self.config.handshake_timeout);
        self.platform.handle_peer_status(peer, entry.status);

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
        if let Some(entry) = state.peers.get_mut(&peer) {
            if entry.status == PeerStatus::Connecting {
                if entry
                    .handshake_deadline
                    .is_some_and(|deadline| deadline <= Instant::now())
                {
                    entry.status = PeerStatus::Disconnected;
                    entry.pending_hello = None;
                    entry.session_key = None;
                    entry.handshake_deadline = None;
                    self.platform.handle_peer_status(peer, entry.status);
                }
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
        .filter_map(|(peer, record)| record.handshake_deadline.map(|deadline| (*peer, deadline)))
        .min_by_key(|(_, deadline)| *deadline)
}
