use std::{cell::Cell, mem, time::Instant};

use bc_components::{
    MLDSAPrivateKey, MLDSAPublicKey, MLKEMPrivateKey, MLKEMPublicKey, SymmetricKey, MLDSA, MLKEM,
};

use super::*;
use crate::{
    platform::QlCrypto,
    wire::{
        self,
        stream::{BodyChunk, StreamFrame, StreamFrameAccept, StreamMessage},
        QlHeader,
    },
    Peer,
};

struct TestCrypto {
    signing_private: MLDSAPrivateKey,
    signing_public: MLDSAPublicKey,
    encapsulation_private: MLKEMPrivateKey,
    encapsulation_public: MLKEMPublicKey,
    nonce_seed: u8,
    nonce_counter: Cell<u8>,
}

impl TestCrypto {
    fn new(seed: u8) -> Self {
        let (signing_private, signing_public) = MLDSA::MLDSA44.keypair();
        let (encapsulation_private, encapsulation_public) = MLKEM::MLKEM512.keypair();
        Self {
            signing_private,
            signing_public,
            encapsulation_private,
            encapsulation_public,
            nonce_seed: seed,
            nonce_counter: Cell::new(0),
        }
    }

    fn peer(&self) -> Peer {
        Peer {
            peer: self.xid(),
            signing_key: self.signing_public.clone(),
            encapsulation_key: self.encapsulation_public.clone(),
        }
    }
}

impl QlCrypto for TestCrypto {
    fn signing_private_key(&self) -> &MLDSAPrivateKey {
        &self.signing_private
    }

    fn signing_public_key(&self) -> &MLDSAPublicKey {
        &self.signing_public
    }

    fn encapsulation_private_key(&self) -> &MLKEMPrivateKey {
        &self.encapsulation_private
    }

    fn encapsulation_public_key(&self) -> &MLKEMPublicKey {
        &self.encapsulation_public
    }

    fn fill_random_bytes(&self, data: &mut [u8]) {
        let value = self.nonce_seed.wrapping_add(self.nonce_counter.get());
        self.nonce_counter
            .set(self.nonce_counter.get().wrapping_add(1));
        data.fill(value);
    }
}

#[derive(Clone, Copy)]
enum Side {
    A,
    B,
}

impl Side {
    fn other(self) -> Self {
        match self {
            Side::A => Side::B,
            Side::B => Side::A,
        }
    }
}

struct Harness {
    now: Instant,
    a: Engine,
    b: Engine,
    crypto_a: TestCrypto,
    crypto_b: TestCrypto,
    outputs_a: Vec<EngineOutput>,
    outputs_b: Vec<EngineOutput>,
}

fn run_engine(
    engine: &mut Engine,
    now: Instant,
    input: EngineInput,
    crypto: &TestCrypto,
) -> Vec<EngineOutput> {
    let mut outputs = Vec::new();
    engine.run_tick(now, input, crypto, &mut |output| outputs.push(output));
    outputs
}

fn take_single_write(outputs: &[EngineOutput]) -> (Token, Option<TrackedWrite>, Vec<u8>) {
    let writes: Vec<_> = outputs
        .iter()
        .filter_map(|output| match output {
            EngineOutput::WriteMessage {
                token,
                tracked,
                bytes,
            } => Some((*token, *tracked, bytes.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(writes.len(), 1);
    writes.into_iter().next().unwrap()
}

impl Harness {
    fn new(config: EngineConfig) -> Self {
        let crypto_a = TestCrypto::new(1);
        let crypto_b = TestCrypto::new(2);
        let peer_a = crypto_a.peer();
        let peer_b = crypto_b.peer();
        let session_key = SymmetricKey::from_data([7; SymmetricKey::SYMMETRIC_KEY_SIZE]);
        let mut a = Engine::new(config, crypto_a.xid(), Some(peer_b));
        let mut b = Engine::new(config, crypto_b.xid(), Some(peer_a));
        a.state.peer.as_mut().unwrap().session = PeerSession::Connected {
            session_key: session_key.clone(),
            keepalive: KeepAliveState::default(),
        };
        b.state.peer.as_mut().unwrap().session = PeerSession::Connected {
            session_key,
            keepalive: KeepAliveState::default(),
        };
        Self {
            now: Instant::now(),
            a,
            b,
            crypto_a,
            crypto_b,
            outputs_a: Vec::new(),
            outputs_b: Vec::new(),
        }
    }

    fn send_a(&mut self, input: EngineInput) {
        self.run_side(Side::A, input);
    }

    fn send_b(&mut self, input: EngineInput) {
        self.run_side(Side::B, input);
    }

    fn drain_a(&mut self) -> Vec<EngineOutput> {
        mem::take(&mut self.outputs_a)
    }

    fn drain_b(&mut self) -> Vec<EngineOutput> {
        mem::take(&mut self.outputs_b)
    }

    fn run_side(&mut self, side: Side, input: EngineInput) {
        let mut outputs = Vec::new();
        match side {
            Side::A => self
                .a
                .run_tick(self.now, input, &self.crypto_a, &mut |output| {
                    outputs.push(output)
                }),
            Side::B => self
                .b
                .run_tick(self.now, input, &self.crypto_b, &mut |output| {
                    outputs.push(output)
                }),
        }

        let writes: Vec<(Token, Option<TrackedWrite>, Vec<u8>)> = outputs
            .iter()
            .filter_map(|output| match output {
                EngineOutput::WriteMessage {
                    token,
                    tracked,
                    bytes,
                } => Some((*token, *tracked, bytes.clone())),
                _ => None,
            })
            .collect();

        match side {
            Side::A => self.outputs_a.extend(outputs),
            Side::B => self.outputs_b.extend(outputs),
        }

        for (token, tracked, bytes) in writes {
            self.run_side(
                side,
                EngineInput::WriteCompleted {
                    token,
                    tracked,
                    result: Ok(()),
                },
            );
            self.run_side(side.other(), EngineInput::Incoming(bytes));
        }
    }
}

#[test]
fn open_prefix_is_delivered_on_setup_output() {
    let mut harness = Harness::new(EngineConfig::default());
    let request_prefix = BodyChunk {
        offset: 0,
        bytes: b"req".to_vec(),
        fin: true,
    };

    harness.send_a(EngineInput::OpenStream {
        open_id: OpenId(1),
        request_head: b"open-head".to_vec(),
        request_prefix: Some(request_prefix.clone()),
        config: StreamConfig::default(),
    });

    let outputs_a = harness.drain_a();
    let outputs_b = harness.drain_b();
    let stream_id = outputs_a
        .iter()
        .find_map(|output| match output {
            EngineOutput::OpenStarted { stream_id, .. } => Some(*stream_id),
            _ => None,
        })
        .unwrap();

    assert!(outputs_a.iter().any(|output| matches!(
        output,
        EngineOutput::OpenStarted {
            open_id: OpenId(1),
            stream_id: id,
        } if *id == stream_id
    )));
    assert!(
        StreamNamespace::for_local(harness.crypto_a.xid(), harness.crypto_b.xid())
            .matches(stream_id)
    );
    assert!(outputs_a.iter().any(|output| matches!(
        output,
        EngineOutput::OutboundClosed {
            stream_id: id,
            dir: Direction::Request,
        } if *id == stream_id
    )));

    let opened = outputs_b.iter().find_map(|output| match output {
        EngineOutput::InboundStreamOpened {
            stream_id,
            request_head,
            request_prefix,
        } => Some((*stream_id, request_head.clone(), request_prefix.clone())),
        _ => None,
    });
    assert_eq!(
        opened,
        Some((
            stream_id,
            b"open-head".to_vec(),
            Some(request_prefix.clone()),
        ))
    );
    assert!(!outputs_b
        .iter()
        .any(|output| matches!(output, EngineOutput::InboundData { .. })));
    assert!(!outputs_b
        .iter()
        .any(|output| matches!(output, EngineOutput::InboundFinished { .. })));
}

#[test]
fn unary_exchange_uses_open_and_accept_prefixes() {
    let mut harness = Harness::new(EngineConfig::default());
    let request_prefix = BodyChunk {
        offset: 0,
        bytes: b"req".to_vec(),
        fin: true,
    };
    let response_prefix = BodyChunk {
        offset: 0,
        bytes: b"resp".to_vec(),
        fin: true,
    };

    harness.send_a(EngineInput::OpenStream {
        open_id: OpenId(7),
        request_head: b"request-head".to_vec(),
        request_prefix: Some(request_prefix.clone()),
        config: StreamConfig::default(),
    });

    let outputs_a_open = harness.drain_a();
    let outputs_b = harness.drain_b();
    let started_stream_id = outputs_a_open
        .iter()
        .find_map(|output| match output {
            EngineOutput::OpenStarted { stream_id, .. } => Some(*stream_id),
            _ => None,
        })
        .unwrap();
    let stream_id = outputs_b
        .iter()
        .find_map(|output| match output {
            EngineOutput::InboundStreamOpened { stream_id, .. } => Some(*stream_id),
            _ => None,
        })
        .unwrap();
    assert_eq!(stream_id, started_stream_id);

    harness.send_b(EngineInput::AcceptStream {
        stream_id,
        response_head: b"response-head".to_vec(),
        response_prefix: Some(response_prefix.clone()),
    });

    let outputs_a = harness.drain_a();
    let outputs_b = harness.drain_b();

    let accepted = outputs_a.iter().find_map(|output| match output {
        EngineOutput::OpenAccepted {
            open_id,
            stream_id,
            response_head,
            response_prefix,
        } => Some((
            *open_id,
            *stream_id,
            response_head.clone(),
            response_prefix.clone(),
        )),
        _ => None,
    });
    assert_eq!(
        accepted,
        Some((
            OpenId(7),
            stream_id,
            b"response-head".to_vec(),
            Some(response_prefix.clone()),
        ))
    );
    assert!(!outputs_a
        .iter()
        .any(|output| matches!(output, EngineOutput::InboundData { .. })));
    assert!(!outputs_a
        .iter()
        .any(|output| matches!(output, EngineOutput::InboundFinished { .. })));
    assert!(outputs_b.iter().any(|output| matches!(
        output,
        EngineOutput::OutboundClosed {
            stream_id: id,
            dir: Direction::Response,
        } if *id == stream_id
    )));
}

#[test]
fn simultaneous_opens_use_disjoint_stream_id_namespaces() {
    let config = EngineConfig::default();
    let crypto_a = TestCrypto::new(11);
    let crypto_b = TestCrypto::new(22);
    let peer_a = crypto_a.peer();
    let peer_b = crypto_b.peer();
    let session_key = SymmetricKey::from_data([9; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let mut a = Engine::new(config, crypto_a.xid(), Some(peer_b));
    let mut b = Engine::new(config, crypto_b.xid(), Some(peer_a));
    a.state.peer.as_mut().unwrap().session = PeerSession::Connected {
        session_key: session_key.clone(),
        keepalive: KeepAliveState::default(),
    };
    b.state.peer.as_mut().unwrap().session = PeerSession::Connected {
        session_key,
        keepalive: KeepAliveState::default(),
    };
    let now = Instant::now();

    let outputs_a_open = run_engine(
        &mut a,
        now,
        EngineInput::OpenStream {
            open_id: OpenId(1),
            request_head: b"a-open".to_vec(),
            request_prefix: None,
            config: StreamConfig::default(),
        },
        &crypto_a,
    );
    let outputs_b_open = run_engine(
        &mut b,
        now,
        EngineInput::OpenStream {
            open_id: OpenId(2),
            request_head: b"b-open".to_vec(),
            request_prefix: None,
            config: StreamConfig::default(),
        },
        &crypto_b,
    );

    let stream_id_a = outputs_a_open
        .iter()
        .find_map(|output| match output {
            EngineOutput::OpenStarted { stream_id, .. } => Some(*stream_id),
            _ => None,
        })
        .unwrap();
    let stream_id_b = outputs_b_open
        .iter()
        .find_map(|output| match output {
            EngineOutput::OpenStarted { stream_id, .. } => Some(*stream_id),
            _ => None,
        })
        .unwrap();

    assert_ne!(stream_id_a, stream_id_b);
    assert!(StreamNamespace::for_local(crypto_a.xid(), crypto_b.xid()).matches(stream_id_a));
    assert!(StreamNamespace::for_local(crypto_b.xid(), crypto_a.xid()).matches(stream_id_b));

    let (token_a, tracked_a, bytes_a) = take_single_write(&outputs_a_open);
    let (token_b, tracked_b, bytes_b) = take_single_write(&outputs_b_open);

    let _ = run_engine(
        &mut a,
        now,
        EngineInput::WriteCompleted {
            token: token_a,
            tracked: tracked_a,
            result: Ok(()),
        },
        &crypto_a,
    );
    let _ = run_engine(
        &mut b,
        now,
        EngineInput::WriteCompleted {
            token: token_b,
            tracked: tracked_b,
            result: Ok(()),
        },
        &crypto_b,
    );

    let outputs_a_incoming = run_engine(&mut a, now, EngineInput::Incoming(bytes_b), &crypto_a);
    let outputs_b_incoming = run_engine(&mut b, now, EngineInput::Incoming(bytes_a), &crypto_b);

    assert!(outputs_a_incoming.iter().any(|output| matches!(
        output,
        EngineOutput::InboundStreamOpened {
            stream_id,
            request_head,
            ..
        } if *stream_id == stream_id_b && request_head == b"b-open"
    )));
    assert!(outputs_b_incoming.iter().any(|output| matches!(
        output,
        EngineOutput::InboundStreamOpened {
            stream_id,
            request_head,
            ..
        } if *stream_id == stream_id_a && request_head == b"a-open"
    )));
    assert_eq!(a.streams.len(), 2);
    assert_eq!(b.streams.len(), 2);
}

#[test]
fn invalid_future_frame_does_not_ack_outstanding_open() {
    let config = EngineConfig::default();
    let crypto_a = TestCrypto::new(31);
    let crypto_b = TestCrypto::new(32);
    let peer_a = crypto_a.peer();
    let peer_b = crypto_b.peer();
    let session_key = SymmetricKey::from_data([5; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let mut a = Engine::new(config, crypto_a.xid(), Some(peer_b));
    let mut _b = Engine::new(config, crypto_b.xid(), Some(peer_a));
    a.state.peer.as_mut().unwrap().session = PeerSession::Connected {
        session_key: session_key.clone(),
        keepalive: KeepAliveState::default(),
    };

    let now = Instant::now();
    let outputs_open = run_engine(
        &mut a,
        now,
        EngineInput::OpenStream {
            open_id: OpenId(9),
            request_head: b"open".to_vec(),
            request_prefix: None,
            config: StreamConfig::default(),
        },
        &crypto_a,
    );
    let stream_id = outputs_open
        .iter()
        .find_map(|output| match output {
            EngineOutput::OpenStarted { stream_id, .. } => Some(*stream_id),
            _ => None,
        })
        .unwrap();

    let message = StreamMessage {
        tx_seq: StreamSeq(2),
        ack_seq: Some(StreamSeq(1)),
        valid_until: wire::now_secs().saturating_add(60),
        frame: StreamFrame::Accept(StreamFrameAccept {
            stream_id,
            response_head: Vec::new(),
            response_prefix: None,
        }),
    };

    let record = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &message,
        [9; wire::encrypted_message::NONCE_SIZE],
    );

    let outputs_incoming = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&record)),
        &crypto_a,
    );

    assert!(!outputs_incoming
        .iter()
        .any(|output| matches!(output, EngineOutput::OpenAccepted { .. })));

    let stream = a.streams.get(&stream_id).unwrap();
    assert!(stream.control().awaiting.is_some());
    match stream {
        StreamState::Initiator(state) => {
            assert!(matches!(state.accept, InitiatorAccept::Opening(_)));
        }
        StreamState::Responder(_) => panic!("expected initiator stream"),
    }
}
