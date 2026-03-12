use std::{cell::Cell, mem, time::Instant};

use bc_components::{
    MLDSAPrivateKey, MLDSAPublicKey, MLKEMPrivateKey, MLKEMPublicKey, SymmetricKey, MLDSA, MLKEM,
};

use super::*;
use crate::{platform::QlCrypto, wire::stream::BodyChunk, Peer};

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

impl Harness {
    fn new(config: EngineConfig) -> Self {
        let crypto_a = TestCrypto::new(1);
        let crypto_b = TestCrypto::new(2);
        let peer_a = crypto_a.peer();
        let peer_b = crypto_b.peer();
        let session_key = SymmetricKey::from_data([7; SymmetricKey::SYMMETRIC_KEY_SIZE]);
        let mut a = Engine::new(config, Some(peer_b));
        let mut b = Engine::new(config, Some(peer_a));
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
    let mut harness = Harness::new(EngineConfig {
        max_payload_bytes: 64,
        ..Default::default()
    });
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

    assert!(outputs_a.iter().any(|output| matches!(
        output,
        EngineOutput::OpenStarted {
            open_id: OpenId(1),
            stream_id: StreamId(1),
        }
    )));
    assert!(outputs_a.iter().any(|output| matches!(
        output,
        EngineOutput::OutboundClosed {
            stream_id: StreamId(1),
            dir: Direction::Request,
        }
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
            StreamId(1),
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
    let mut harness = Harness::new(EngineConfig {
        max_payload_bytes: 64,
        ..Default::default()
    });
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

    let _outputs_a = harness.drain_a();
    let outputs_b = harness.drain_b();
    let stream_id = outputs_b
        .iter()
        .find_map(|output| match output {
            EngineOutput::InboundStreamOpened { stream_id, .. } => Some(*stream_id),
            _ => None,
        })
        .unwrap();

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
            StreamId(1),
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
            stream_id: StreamId(1),
            dir: Direction::Response,
        }
    )));
}
