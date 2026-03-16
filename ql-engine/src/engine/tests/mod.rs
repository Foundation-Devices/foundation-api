mod handshake;
mod liveness;
mod peer;
mod stream;

use std::{
    cell::Cell,
    mem,
    ops::{Deref, DerefMut},
    time::{Duration, Instant},
};

use bc_components::{SymmetricKey, MLDSA, MLKEM, XID};

use crate::{
    engine::*,
    identity::QlIdentity,
    stream::{state::*, StreamNamespace},
    wire::{self, stream::*, QlHeader, QlPayload, QlRecord, StreamSeq},
    PacketId, Peer,
};

#[derive(Clone)]
struct TestCrypto {
    nonce_seed: u8,
    nonce_counter: Cell<u8>,
}

impl TestCrypto {
    fn new(seed: u8) -> Self {
        Self {
            nonce_seed: seed,
            nonce_counter: Cell::new(0),
        }
    }
}

impl QlCrypto for TestCrypto {
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
    a: EngineWrapper,
    b: EngineWrapper,
}

struct SingleEngineHarness {
    now: Instant,
    engine: EngineWrapper,
    peer: QlIdentity,
    session_key: SymmetricKey,
}

impl SingleEngineHarness {
    fn connected(config: EngineConfig, nonce_seed: u8, session_fill: u8) -> Self {
        let local_identity = test_identity();
        let peer = test_identity();
        let session_key = SymmetricKey::from_data([session_fill; SymmetricKey::SYMMETRIC_KEY_SIZE]);
        let mut engine = Engine::new(
            config,
            local_identity.clone(),
            Some(peer_from_identity(&peer)),
        );
        engine.peer.as_mut().unwrap().session = PeerSession::Connected {
            session_key: session_key.clone(),
            keepalive: KeepAliveState::default(),
            recent_ready: None,
        };
        Self {
            now: Instant::now(),
            engine: EngineWrapper::new(engine, TestCrypto::new(nonce_seed)),
            peer,
            session_key,
        }
    }
}

impl Harness {
    fn connected(config: EngineConfig) -> Self {
        let identity_a = test_identity();
        let identity_b = test_identity();
        let peer_a = peer_from_identity(&identity_a);
        let peer_b = peer_from_identity(&identity_b);
        let crypto_a = TestCrypto::new(1);
        let crypto_b = TestCrypto::new(2);
        let session_key = SymmetricKey::from_data([7; SymmetricKey::SYMMETRIC_KEY_SIZE]);
        let mut a = Engine::new(config, identity_a.clone(), Some(peer_b));
        let mut b = Engine::new(config, identity_b.clone(), Some(peer_a));
        a.peer.as_mut().unwrap().session = PeerSession::Connected {
            session_key: session_key.clone(),
            keepalive: KeepAliveState::default(),
            recent_ready: None,
        };
        b.peer.as_mut().unwrap().session = PeerSession::Connected {
            session_key,
            keepalive: KeepAliveState::default(),
            recent_ready: None,
        };
        Self {
            now: Instant::now(),
            a: EngineWrapper::new(a, crypto_a),
            b: EngineWrapper::new(b, crypto_b),
        }
    }

    fn run_side(&mut self, side: Side, input: EngineInput) {
        match side {
            Side::A => self.a.run_tick(self.now, input),
            Side::B => self.b.run_tick(self.now, input),
        }

        while let Some(write) = match side {
            Side::A => self.a.take_next_write(),
            Side::B => self.b.take_next_write(),
        } {
            let bytes = write.bytes.clone();
            self.complete_side_write(side, write.id, Ok(()));
            self.run_side(side.other(), EngineInput::Incoming(bytes));
        }
    }

    fn complete_side_write(&mut self, side: Side, write_id: WriteId, result: Result<(), QlError>) {
        match side {
            Side::A => self.a.complete_write(write_id, result),
            Side::B => self.b.complete_write(write_id, result),
        }
    }
}

struct EngineWrapper {
    engine: Engine,
    crypto: TestCrypto,
    outputs: Vec<EngineOutput>,
}

impl Deref for EngineWrapper {
    type Target = Engine;

    fn deref(&self) -> &Self::Target {
        &self.engine
    }
}

impl DerefMut for EngineWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.engine
    }
}

impl EngineWrapper {
    fn new(engine: Engine, crypto: TestCrypto) -> Self {
        Self {
            engine,
            crypto,
            outputs: Vec::new(),
        }
    }

    fn run_tick(&mut self, now: Instant, input: EngineInput) {
        self.engine
            .run_tick(now, input, &self.crypto, &mut |output| {
                self.outputs.push(output)
            });
    }

    fn run_tick_collect(&mut self, now: Instant, input: EngineInput) -> Vec<EngineOutput> {
        self.run_tick(now, input);
        self.drain_outputs()
    }

    fn complete_write(&mut self, write_id: WriteId, result: Result<(), QlError>) {
        self.engine
            .complete_write(write_id, result, &mut |output| self.outputs.push(output));
    }

    fn take_next_write(&mut self) -> Option<OutboundWrite> {
        self.engine.take_next_write(&self.crypto)
    }

    fn complete_write_collect(
        &mut self,
        write_id: WriteId,
        result: Result<(), QlError>,
    ) -> Vec<EngineOutput> {
        self.complete_write(write_id, result);
        self.drain_outputs()
    }

    fn open_stream(
        &mut self,
        now: Instant,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
        config: StreamConfig,
    ) -> Result<StreamId, QlError> {
        self.engine
            .open_stream(now, request_head, request_prefix, config)
    }

    fn drain_outputs(&mut self) -> Vec<EngineOutput> {
        mem::take(&mut self.outputs)
    }
}

fn test_identity() -> QlIdentity {
    let (signing_private, signing_public) = MLDSA::MLDSA44.keypair();
    let (encapsulation_private, encapsulation_public) = MLKEM::MLKEM512.keypair();
    QlIdentity::from_keys(
        signing_private,
        signing_public,
        encapsulation_private,
        encapsulation_public,
    )
}

fn peer_from_identity(identity: &QlIdentity) -> Peer {
    Peer {
        peer: identity.xid,
        signing_key: identity.signing_public_key.clone(),
        encapsulation_key: identity.encapsulation_public_key.clone(),
    }
}

fn decode_stream_body(bytes: &[u8], session_key: &SymmetricKey) -> (QlHeader, StreamBody) {
    let record = wire::decode_record(bytes).unwrap();
    let aad = record.header.aad();
    let QlPayload::Stream(encrypted) = record.payload else {
        panic!("expected stream payload");
    };
    let plaintext = encrypted.decrypt(session_key, &aad).unwrap();
    let body = wire::access_value::<wire::stream::ArchivedStreamBody>(&plaintext)
        .and_then(wire::deserialize_value)
        .unwrap();
    (record.header, body)
}

fn encrypt_heartbeat_record(
    sender: XID,
    recipient: XID,
    session_key: &SymmetricKey,
    packet_id: u32,
    nonce: [u8; wire::encrypted_message::NONCE_SIZE],
) -> QlRecord {
    wire::heartbeat::encrypt_heartbeat(
        QlHeader { sender, recipient },
        session_key,
        wire::heartbeat::HeartbeatBody {
            meta: crate::wire::ControlMeta {
                packet_id: PacketId(packet_id),
                valid_until: wire::now_secs().saturating_add(60),
            },
        },
        nonce,
    )
}

fn insert_inflight_gap_stream(engine: &mut EngineWrapper, stream_id: StreamId, now: Instant) {
    let retry_at = now + Duration::from_secs(60);
    let mut stream = StreamState {
        control: StreamControl::default(),
        role: StreamRole::Initiator(InitiatorStream {
            request: OutboundPhase::from_prefix(false),
            response: InboundState::new(),
        }),
    };
    let control = &mut stream.control;
    control.next_tx_seq = StreamSeq(6);
    control.insert_in_flight(InFlightFrame {
        tx_seq: StreamSeq::START,
        frame: StreamFrame::Open(StreamFrameOpen {
            stream_id,
            request_head: b"open".to_vec(),
            request_prefix: None,
        }),
        attempt: 0,
        write_state: InFlightWriteState::WaitingRetry { retry_at },
    });
    for (tx_seq, byte) in [(2, b'a'), (3, b'b'), (4, b'c'), (5, b'd')] {
        control.insert_in_flight(InFlightFrame {
            tx_seq: StreamSeq(tx_seq),
            frame: StreamFrame::Data(StreamFrameData {
                stream_id,
                chunk: BodyChunk {
                    bytes: vec![byte],
                    fin: false,
                },
            }),
            attempt: 0,
            write_state: InFlightWriteState::WaitingRetry { retry_at },
        });
    }
    engine.streams.streams.insert(stream_id, stream);
}

fn insert_inflight_stream_with_data(
    engine: &mut EngineWrapper,
    stream_id: StreamId,
    now: Instant,
    data_seqs: &[u32],
) {
    let retry_at = now + Duration::from_secs(60);
    let mut stream = StreamState {
        control: StreamControl::default(),
        role: StreamRole::Initiator(InitiatorStream {
            request: OutboundPhase::from_prefix(false),
            response: InboundState::new(),
        }),
    };
    let control = &mut stream.control;
    control.next_tx_seq = StreamSeq(data_seqs.iter().copied().max().unwrap_or(1) + 1);
    control.insert_in_flight(InFlightFrame {
        tx_seq: StreamSeq::START,
        frame: StreamFrame::Open(StreamFrameOpen {
            stream_id,
            request_head: b"open".to_vec(),
            request_prefix: None,
        }),
        attempt: 0,
        write_state: InFlightWriteState::WaitingRetry { retry_at },
    });
    for &tx_seq in data_seqs {
        control.insert_in_flight(InFlightFrame {
            tx_seq: StreamSeq(tx_seq),
            frame: StreamFrame::Data(StreamFrameData {
                stream_id,
                chunk: BodyChunk {
                    bytes: vec![b'a' + (tx_seq as u8)],
                    fin: false,
                },
            }),
            attempt: 0,
            write_state: InFlightWriteState::WaitingRetry { retry_at },
        });
    }
    engine.streams.streams.insert(stream_id, stream);
}

fn insert_unwritten_inflight_stream_with_data(
    engine: &mut EngineWrapper,
    stream_id: StreamId,
    _now: Instant,
    data_seqs: &[u32],
) {
    let mut stream = StreamState {
        control: StreamControl::default(),
        role: StreamRole::Initiator(InitiatorStream {
            request: OutboundPhase::from_prefix(false),
            response: InboundState::new(),
        }),
    };
    let control = &mut stream.control;
    control.next_tx_seq = StreamSeq(data_seqs.iter().copied().max().unwrap_or(1) + 1);
    control.insert_in_flight(InFlightFrame {
        tx_seq: StreamSeq::START,
        frame: StreamFrame::Open(StreamFrameOpen {
            stream_id,
            request_head: b"open".to_vec(),
            request_prefix: None,
        }),
        attempt: 0,
        write_state: InFlightWriteState::Ready,
    });
    for &tx_seq in data_seqs {
        control.insert_in_flight(InFlightFrame {
            tx_seq: StreamSeq(tx_seq),
            frame: StreamFrame::Data(StreamFrameData {
                stream_id,
                chunk: BodyChunk {
                    bytes: vec![b'a' + (tx_seq as u8)],
                    fin: false,
                },
            }),
            attempt: 0,
            write_state: InFlightWriteState::Ready,
        });
    }
    engine.streams.streams.insert(stream_id, stream);
}
