use std::{
    cell::Cell,
    mem,
    time::{Duration, Instant},
};

use bc_components::{SymmetricKey, MLDSA, MLKEM};

use super::*;
use crate::{
    platform::{QlCrypto, QlIdentity},
    wire::{
        self,
        stream::{
            BodyChunk, StreamAck, StreamAckBody, StreamBody, StreamFrame, StreamFrameAccept,
            StreamFrameData, StreamFrameOpen, StreamMessage,
        },
        QlHeader, QlPayload,
    },
    PacketId, Peer,
};

struct TestCrypto {
    identity: QlIdentity,
    nonce_seed: u8,
    nonce_counter: Cell<u8>,
}

impl TestCrypto {
    fn new(seed: u8) -> Self {
        let (signing_private, signing_public) = MLDSA::MLDSA44.keypair();
        let (encapsulation_private, encapsulation_public) = MLKEM::MLKEM512.keypair();
        Self {
            identity: QlIdentity::from_keys(
                signing_private,
                signing_public,
                encapsulation_private,
                encapsulation_public,
            ),
            nonce_seed: seed,
            nonce_counter: Cell::new(0),
        }
    }

    fn xid(&self) -> XID {
        self.identity.xid
    }

    fn peer(&self) -> Peer {
        Peer {
            peer: self.xid(),
            signing_key: self.identity.signing_public_key.clone(),
            encapsulation_key: self.identity.encapsulation_public_key.clone(),
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

fn complete_engine_write(
    engine: &mut Engine,
    write_id: WriteId,
    result: Result<(), QlError>,
) -> Vec<EngineOutput> {
    let mut outputs = Vec::new();
    engine.complete_write(write_id, result, &mut |output| outputs.push(output));
    outputs
}

fn take_single_write(engine: &mut Engine, crypto: &TestCrypto) -> OutboundWrite {
    engine
        .take_next_write(crypto)
        .expect("expected single write")
}

fn take_all_writes(engine: &mut Engine, crypto: &TestCrypto) -> Vec<OutboundWrite> {
    let mut writes = Vec::new();
    while let Some(write) = engine.take_next_write(crypto) {
        writes.push(write);
    }
    writes
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

fn connected_engine_with_config(
    config: EngineConfig,
    local: &TestCrypto,
    peer: Peer,
    session_key: SymmetricKey,
) -> Engine {
    let mut engine = Engine::new(config, local.identity.clone(), Some(peer));
    engine.peer.as_mut().unwrap().session = PeerSession::Connected {
        session_key,
        keepalive: KeepAliveState::default(),
    };
    engine
}

fn connected_engine(local: &TestCrypto, peer: Peer, session_key: SymmetricKey) -> Engine {
    connected_engine_with_config(EngineConfig::default(), local, peer, session_key)
}

fn insert_inflight_gap_stream(engine: &mut Engine, stream_id: StreamId, now: Instant) {
    let retry_at = now + Duration::from_secs(60);
    let mut stream = StreamState::Initiator(InitiatorStream {
        meta: StreamMeta {
            stream_id,
            last_activity: now,
        },
        control: StreamControl::default(),
        request: OutboundState::from_prefix(Direction::Request, false),
        response: InboundState::new(),
        accept: InitiatorAccept::Opening(OpenWaiter {
            open_id: Some(OpenId(1)),
            open_timeout_token: Token(999),
        }),
    });
    let control = stream.control_mut();
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
                dir: Direction::Request,
                chunk: BodyChunk {
                    bytes: vec![byte],
                    fin: false,
                },
            }),
            attempt: 0,
            write_state: InFlightWriteState::WaitingRetry { retry_at },
        });
    }
    engine.streams.insert(stream_id, stream);
}

fn insert_inflight_stream_with_data(
    engine: &mut Engine,
    stream_id: StreamId,
    now: Instant,
    data_seqs: &[u32],
) {
    let retry_at = now + Duration::from_secs(60);
    let mut stream = StreamState::Initiator(InitiatorStream {
        meta: StreamMeta {
            stream_id,
            last_activity: now,
        },
        control: StreamControl::default(),
        request: OutboundState::from_prefix(Direction::Request, false),
        response: InboundState::new(),
        accept: InitiatorAccept::Opening(OpenWaiter {
            open_id: Some(OpenId(1)),
            open_timeout_token: Token(1001),
        }),
    });
    let control = stream.control_mut();
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
                dir: Direction::Request,
                chunk: BodyChunk {
                    bytes: vec![b'a' + (tx_seq as u8)],
                    fin: false,
                },
            }),
            attempt: 0,
            write_state: InFlightWriteState::WaitingRetry { retry_at },
        });
    }
    engine.streams.insert(stream_id, stream);
}

fn insert_unwritten_inflight_stream_with_data(
    engine: &mut Engine,
    stream_id: StreamId,
    now: Instant,
    data_seqs: &[u32],
) {
    let mut stream = StreamState::Initiator(InitiatorStream {
        meta: StreamMeta {
            stream_id,
            last_activity: now,
        },
        control: StreamControl::default(),
        request: OutboundState::from_prefix(Direction::Request, false),
        response: InboundState::new(),
        accept: InitiatorAccept::Opening(OpenWaiter {
            open_id: Some(OpenId(2)),
            open_timeout_token: Token(1002),
        }),
    });
    let control = stream.control_mut();
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
                dir: Direction::Request,
                chunk: BodyChunk {
                    bytes: vec![b'a' + (tx_seq as u8)],
                    fin: false,
                },
            }),
            attempt: 0,
            write_state: InFlightWriteState::Ready,
        });
    }
    engine.streams.insert(stream_id, stream);
}

impl Harness {
    fn new(config: EngineConfig) -> Self {
        let crypto_a = TestCrypto::new(1);
        let crypto_b = TestCrypto::new(2);
        let peer_a = crypto_a.peer();
        let peer_b = crypto_b.peer();
        let session_key = SymmetricKey::from_data([7; SymmetricKey::SYMMETRIC_KEY_SIZE]);
        let mut a = Engine::new(config, crypto_a.identity.clone(), Some(peer_b));
        let mut b = Engine::new(config, crypto_b.identity.clone(), Some(peer_a));
        a.peer.as_mut().unwrap().session = PeerSession::Connected {
            session_key: session_key.clone(),
            keepalive: KeepAliveState::default(),
        };
        b.peer.as_mut().unwrap().session = PeerSession::Connected {
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

        match side {
            Side::A => self.outputs_a.extend(outputs),
            Side::B => self.outputs_b.extend(outputs),
        }

        while let Some(write) = match side {
            Side::A => self.a.take_next_write(&self.crypto_a),
            Side::B => self.b.take_next_write(&self.crypto_b),
        } {
            let bytes = write.bytes.clone();
            self.complete_side_write(side, write.id, Ok(()));
            self.run_side(side.other(), EngineInput::Incoming(bytes));
        }
    }

    fn complete_side_write(&mut self, side: Side, write_id: WriteId, result: Result<(), QlError>) {
        let mut outputs = Vec::new();
        match side {
            Side::A => self
                .a
                .complete_write(write_id, result, &mut |output| outputs.push(output)),
            Side::B => self
                .b
                .complete_write(write_id, result, &mut |output| outputs.push(output)),
        }

        match side {
            Side::A => self.outputs_a.extend(outputs),
            Side::B => self.outputs_b.extend(outputs),
        }
    }
}

#[test]
fn open_prefix_is_delivered_on_setup_output() {
    let mut harness = Harness::new(EngineConfig::default());
    let request_prefix = BodyChunk {
        bytes: b"req".to_vec(),
        fin: true,
    };

    harness.send_a(EngineInput::OpenStream {
        open_id: OpenId(1),
        request_head: b"open-head".to_vec(),
        request_prefix: Some(request_prefix.clone()),
        config: StreamConfig::default(),
    });

    harness.now += EngineConfig::default().stream_ack_delay;
    harness.send_b(EngineInput::TimerExpired);

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
        bytes: b"req".to_vec(),
        fin: true,
    };
    let response_prefix = BodyChunk {
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

    harness.now += EngineConfig::default().stream_ack_delay;
    harness.send_a(EngineInput::TimerExpired);

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
    let mut a = Engine::new(config, crypto_a.identity.clone(), Some(peer_b));
    let mut b = Engine::new(config, crypto_b.identity.clone(), Some(peer_a));
    a.peer.as_mut().unwrap().session = PeerSession::Connected {
        session_key: session_key.clone(),
        keepalive: KeepAliveState::default(),
    };
    b.peer.as_mut().unwrap().session = PeerSession::Connected {
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

    let write_a = take_single_write(&mut a, &crypto_a);
    let write_b = take_single_write(&mut b, &crypto_b);

    let _ = complete_engine_write(&mut a, write_a.id, Ok(()));
    let _ = complete_engine_write(&mut b, write_b.id, Ok(()));

    let outputs_a_incoming =
        run_engine(&mut a, now, EngineInput::Incoming(write_b.bytes), &crypto_a);
    let outputs_b_incoming =
        run_engine(&mut b, now, EngineInput::Incoming(write_a.bytes), &crypto_b);

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
    let mut a = Engine::new(config, crypto_a.identity.clone(), Some(peer_b));
    let mut _b = Engine::new(config, crypto_b.identity.clone(), Some(peer_a));
    a.peer.as_mut().unwrap().session = PeerSession::Connected {
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
        ack: Some(crate::wire::stream::StreamAck {
            base: StreamSeq(0),
            bitmap: 0,
        }),
        valid_until: wire::now_secs().saturating_add(60),
        frame: StreamFrame::Accept(StreamFrameAccept {
            stream_id,
            response_head: Vec::new(),
            response_prefix: None,
        }),
    };

    let body = StreamBody::Message(message);
    let record = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &body,
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
    assert!(stream.control().in_flight.contains_key(&StreamSeq::START));
    match stream {
        StreamState::Initiator(state) => {
            assert!(matches!(state.accept, InitiatorAccept::Opening(_)));
        }
        _ => panic!("expected initiator stream"),
    }
}

#[test]
fn out_of_order_remote_stream_buffers_until_open_arrives() {
    let config = EngineConfig::default();
    let crypto_a = TestCrypto::new(41);
    let crypto_b = TestCrypto::new(42);
    let peer_b = crypto_b.peer();
    let session_key = SymmetricKey::from_data([6; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let mut a = Engine::new(config, crypto_a.identity.clone(), Some(peer_b));
    a.peer.as_mut().unwrap().session = PeerSession::Connected {
        session_key: session_key.clone(),
        keepalive: KeepAliveState::default(),
    };

    let now = Instant::now();
    let stream_id = StreamId(StreamNamespace::for_local(crypto_b.xid(), crypto_a.xid()).bit() | 1);

    let data_message = StreamMessage {
        tx_seq: StreamSeq(2),
        ack: None,
        valid_until: wire::now_secs().saturating_add(60),
        frame: StreamFrame::Data(crate::wire::stream::StreamFrameData {
            stream_id,
            dir: Direction::Request,
            chunk: BodyChunk {
                bytes: b"hello".to_vec(),
                fin: false,
            },
        }),
    };
    let data_body = StreamBody::Message(data_message);
    let data_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &data_body,
        [11; wire::encrypted_message::NONCE_SIZE],
    );

    let outputs_data = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&data_record)),
        &crypto_a,
    );

    assert!(!outputs_data
        .iter()
        .any(|output| matches!(output, EngineOutput::InboundStreamOpened { .. })));
    assert!(!outputs_data
        .iter()
        .any(|output| matches!(output, EngineOutput::InboundData { .. })));
    assert!(a.take_next_write(&crypto_a).is_some());
    assert!(matches!(
        a.streams.get(&stream_id),
        Some(StreamState::Provisional(_))
    ));

    let open_message = StreamMessage {
        tx_seq: StreamSeq(1),
        ack: None,
        valid_until: wire::now_secs().saturating_add(60),
        frame: StreamFrame::Open(crate::wire::stream::StreamFrameOpen {
            stream_id,
            request_head: b"late-open".to_vec(),
            request_prefix: None,
        }),
    };
    let open_body = StreamBody::Message(open_message);
    let open_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &open_body,
        [12; wire::encrypted_message::NONCE_SIZE],
    );

    let outputs_open = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&open_record)),
        &crypto_a,
    );

    assert!(outputs_open.iter().any(|output| matches!(
        output,
        EngineOutput::InboundStreamOpened {
            stream_id: id,
            request_head,
            request_prefix: None,
        } if *id == stream_id && request_head == b"late-open"
    )));
    assert!(outputs_open.iter().any(|output| matches!(
        output,
        EngineOutput::InboundData {
            stream_id: id,
            dir: Direction::Request,
            bytes,
        } if *id == stream_id && bytes == b"hello"
    )));
}

#[test]
fn out_of_order_response_data_waits_for_accept() {
    let config = EngineConfig::default();
    let crypto_a = TestCrypto::new(51);
    let crypto_b = TestCrypto::new(52);
    let peer_b = crypto_b.peer();
    let session_key = SymmetricKey::from_data([4; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let mut a = Engine::new(config, crypto_a.identity.clone(), Some(peer_b));
    a.peer.as_mut().unwrap().session = PeerSession::Connected {
        session_key: session_key.clone(),
        keepalive: KeepAliveState::default(),
    };

    let now = Instant::now();
    let outputs_open = run_engine(
        &mut a,
        now,
        EngineInput::OpenStream {
            open_id: OpenId(12),
            request_head: b"req".to_vec(),
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

    let data_message = StreamMessage {
        tx_seq: StreamSeq(2),
        ack: None,
        valid_until: wire::now_secs().saturating_add(60),
        frame: StreamFrame::Data(crate::wire::stream::StreamFrameData {
            stream_id,
            dir: Direction::Response,
            chunk: BodyChunk {
                bytes: b"resp".to_vec(),
                fin: false,
            },
        }),
    };
    let data_body = StreamBody::Message(data_message);
    let data_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &data_body,
        [21; wire::encrypted_message::NONCE_SIZE],
    );

    let outputs_data = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&data_record)),
        &crypto_a,
    );
    assert!(!outputs_data
        .iter()
        .any(|output| matches!(output, EngineOutput::OpenAccepted { .. })));
    assert!(!outputs_data
        .iter()
        .any(|output| matches!(output, EngineOutput::InboundData { .. })));

    let accept_message = StreamMessage {
        tx_seq: StreamSeq(1),
        ack: None,
        valid_until: wire::now_secs().saturating_add(60),
        frame: StreamFrame::Accept(StreamFrameAccept {
            stream_id,
            response_head: b"resp-head".to_vec(),
            response_prefix: None,
        }),
    };
    let accept_body = StreamBody::Message(accept_message);
    let accept_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &accept_body,
        [22; wire::encrypted_message::NONCE_SIZE],
    );

    let outputs_accept = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&accept_record)),
        &crypto_a,
    );

    assert!(outputs_accept.iter().any(|output| matches!(
        output,
        EngineOutput::OpenAccepted {
            open_id: OpenId(12),
            stream_id: id,
            response_head,
            response_prefix: None,
        } if *id == stream_id && response_head == b"resp-head"
    )));
    assert!(outputs_accept.iter().any(|output| matches!(
        output,
        EngineOutput::InboundData {
            stream_id: id,
            dir: Direction::Response,
            bytes,
        } if *id == stream_id && bytes == b"resp"
    )));
}

#[test]
fn delayed_ack_only_does_not_consume_sequence_space() {
    let mut harness = Harness::new(EngineConfig::default());

    harness.send_a(EngineInput::OpenStream {
        open_id: OpenId(21),
        request_head: b"open-head".to_vec(),
        request_prefix: None,
        config: StreamConfig::default(),
    });

    let outputs_a = harness.drain_a();
    let _outputs_b = harness.drain_b();
    let stream_id = outputs_a
        .iter()
        .find_map(|output| match output {
            EngineOutput::OpenStarted { stream_id, .. } => Some(*stream_id),
            _ => None,
        })
        .unwrap();

    harness.now += EngineConfig::default().stream_ack_delay;
    harness.send_b(EngineInput::TimerExpired);

    let _outputs_b = harness.drain_b();

    let stream = harness.b.streams.get(&stream_id).unwrap();
    assert!(stream.control().in_flight.is_empty());
    assert_eq!(stream.control().next_tx_seq, StreamSeq::START);
}

#[test]
fn half_window_progress_flushes_ack_before_timer() {
    let config = EngineConfig::default();
    let crypto_a = TestCrypto::new(61);
    let crypto_b = TestCrypto::new(62);
    let peer_b = crypto_b.peer();
    let session_key = SymmetricKey::from_data([8; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let mut a = Engine::new(config, crypto_a.identity.clone(), Some(peer_b));
    a.peer.as_mut().unwrap().session = PeerSession::Connected {
        session_key: session_key.clone(),
        keepalive: KeepAliveState::default(),
    };

    let now = Instant::now();
    let stream_id = StreamId(StreamNamespace::for_local(crypto_b.xid(), crypto_a.xid()).bit() | 1);
    let messages = [
        StreamMessage {
            tx_seq: StreamSeq(1),
            ack: None,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Open(crate::wire::stream::StreamFrameOpen {
                stream_id,
                request_head: b"open".to_vec(),
                request_prefix: None,
            }),
        },
        StreamMessage {
            tx_seq: StreamSeq(2),
            ack: None,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Data(crate::wire::stream::StreamFrameData {
                stream_id,
                dir: Direction::Request,
                chunk: BodyChunk {
                    bytes: b"a".to_vec(),
                    fin: false,
                },
            }),
        },
        StreamMessage {
            tx_seq: StreamSeq(3),
            ack: None,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Data(crate::wire::stream::StreamFrameData {
                stream_id,
                dir: Direction::Request,
                chunk: BodyChunk {
                    bytes: b"b".to_vec(),
                    fin: false,
                },
            }),
        },
        StreamMessage {
            tx_seq: StreamSeq(4),
            ack: None,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Data(crate::wire::stream::StreamFrameData {
                stream_id,
                dir: Direction::Request,
                chunk: BodyChunk {
                    bytes: b"c".to_vec(),
                    fin: false,
                },
            }),
        },
    ];

    for message in messages.iter().take(3) {
        let body = StreamBody::Message(message.clone());
        let record = wire::stream::encrypt_stream(
            QlHeader {
                sender: crypto_b.xid(),
                recipient: crypto_a.xid(),
            },
            &session_key,
            &body,
            [message.tx_seq.0 as u8; wire::encrypted_message::NONCE_SIZE],
        );
        let _outputs = run_engine(
            &mut a,
            now,
            EngineInput::Incoming(wire::encode_record(&record)),
            &crypto_a,
        );
        assert!(a.take_next_write(&crypto_a).is_none());
    }

    let body = StreamBody::Message(messages[3].clone());
    let record = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &body,
        [4; wire::encrypted_message::NONCE_SIZE],
    );
    let _outputs = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&record)),
        &crypto_a,
    );

    let ack_write = take_single_write(&mut a, &crypto_a);
    let (_, ack_body) = decode_stream_body(&ack_write.bytes, &session_key);
    assert!(matches!(ack_body, StreamBody::Ack(_)));
}

#[test]
fn out_of_order_loss_reports_selective_ack_bitmap() {
    let crypto_a = TestCrypto::new(71);
    let crypto_b = TestCrypto::new(72);
    let session_key = SymmetricKey::from_data([3; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let peer_b = crypto_b.peer();
    let mut a = connected_engine(&crypto_a, peer_b, session_key.clone());

    let now = Instant::now();
    let stream_id = StreamId(StreamNamespace::for_local(crypto_b.xid(), crypto_a.xid()).bit() | 1);
    let messages = [
        StreamMessage {
            tx_seq: StreamSeq(1),
            ack: None,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Open(StreamFrameOpen {
                stream_id,
                request_head: b"open".to_vec(),
                request_prefix: None,
            }),
        },
        StreamMessage {
            tx_seq: StreamSeq(2),
            ack: None,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Data(StreamFrameData {
                stream_id,
                dir: Direction::Request,
                chunk: BodyChunk {
                    bytes: b"a".to_vec(),
                    fin: false,
                },
            }),
        },
        StreamMessage {
            tx_seq: StreamSeq(4),
            ack: None,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Data(StreamFrameData {
                stream_id,
                dir: Direction::Request,
                chunk: BodyChunk {
                    bytes: b"c".to_vec(),
                    fin: false,
                },
            }),
        },
        StreamMessage {
            tx_seq: StreamSeq(5),
            ack: None,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Data(StreamFrameData {
                stream_id,
                dir: Direction::Request,
                chunk: BodyChunk {
                    bytes: b"d".to_vec(),
                    fin: false,
                },
            }),
        },
    ];

    for message in &messages[..2] {
        let record = wire::stream::encrypt_stream(
            QlHeader {
                sender: crypto_b.xid(),
                recipient: crypto_a.xid(),
            },
            &session_key,
            &StreamBody::Message(message.clone()),
            [message.tx_seq.0 as u8; wire::encrypted_message::NONCE_SIZE],
        );
        let _outputs = run_engine(
            &mut a,
            now,
            EngineInput::Incoming(wire::encode_record(&record)),
            &crypto_a,
        );
        assert!(a.take_next_write(&crypto_a).is_none());
    }

    let record4 = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &StreamBody::Message(messages[2].clone()),
        [4; wire::encrypted_message::NONCE_SIZE],
    );
    let outputs4 = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&record4)),
        &crypto_a,
    );
    let ack_write4 = take_single_write(&mut a, &crypto_a);
    let (_, ack_body4) = decode_stream_body(&ack_write4.bytes, &session_key);
    assert!(matches!(
        ack_body4,
        StreamBody::Ack(StreamAckBody {
            stream_id: id,
            ack: StreamAck {
                base: StreamSeq(2),
                bitmap: 0b0000_0010,
            },
            ..
        }) if id == stream_id
    ));
    assert!(!outputs4
        .iter()
        .any(|output| matches!(output, EngineOutput::InboundData { .. })));
    let _ = complete_engine_write(&mut a, ack_write4.id, Ok(()));

    let record5 = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &StreamBody::Message(messages[3].clone()),
        [5; wire::encrypted_message::NONCE_SIZE],
    );
    let outputs5 = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&record5)),
        &crypto_a,
    );
    let ack_write5 = take_single_write(&mut a, &crypto_a);
    let (_, ack_body5) = decode_stream_body(&ack_write5.bytes, &session_key);
    assert!(matches!(
        ack_body5,
        StreamBody::Ack(StreamAckBody {
            stream_id: id,
            ack: StreamAck {
                base: StreamSeq(2),
                bitmap: 0b0000_0110,
            },
            ..
        }) if id == stream_id
    ));
    assert!(!outputs5
        .iter()
        .any(|output| matches!(output, EngineOutput::InboundData { .. })));
}

#[test]
fn selective_ack_only_body_retires_acked_gap_tail() {
    let crypto_a = TestCrypto::new(81);
    let crypto_b = TestCrypto::new(82);
    let session_key = SymmetricKey::from_data([2; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let peer_b = crypto_b.peer();
    let mut a = connected_engine(&crypto_a, peer_b, session_key.clone());

    let now = Instant::now();
    let stream_id = a
        .state
        .next_stream_id(StreamNamespace::for_local(crypto_a.xid(), crypto_b.xid()));
    insert_inflight_gap_stream(&mut a, stream_id, now);

    let ack_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &StreamBody::Ack(StreamAckBody {
            stream_id,
            ack: StreamAck {
                base: StreamSeq(2),
                bitmap: 0b0000_0110,
            },
            valid_until: wire::now_secs().saturating_add(60),
        }),
        [9; wire::encrypted_message::NONCE_SIZE],
    );

    let outputs = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&ack_record)),
        &crypto_a,
    );

    assert!(!outputs
        .iter()
        .any(|output| matches!(output, EngineOutput::OutboundFailed { .. })));
    let stream = a.streams.get(&stream_id).unwrap();
    let remaining: Vec<_> = stream
        .control()
        .in_flight
        .iter()
        .map(|(seq, _)| seq)
        .collect();
    assert_eq!(remaining, vec![StreamSeq(3)]);
    assert_eq!(stream.control().next_tx_seq, StreamSeq(6));
}

#[test]
fn fast_retransmit_resends_oldest_gap_when_threshold_met() {
    let crypto_a = TestCrypto::new(83);
    let crypto_b = TestCrypto::new(84);
    let session_key = SymmetricKey::from_data([9; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let peer_b = crypto_b.peer();
    let mut config = EngineConfig::default();
    config.stream_fast_retransmit_threshold = 2;
    let mut a = connected_engine_with_config(config, &crypto_a, peer_b, session_key.clone());

    let now = Instant::now();
    let stream_id = a
        .state
        .next_stream_id(StreamNamespace::for_local(crypto_a.xid(), crypto_b.xid()));
    insert_inflight_gap_stream(&mut a, stream_id, now);

    let ack_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &StreamBody::Ack(StreamAckBody {
            stream_id,
            ack: StreamAck {
                base: StreamSeq(2),
                bitmap: 0b0000_0110,
            },
            valid_until: wire::now_secs().saturating_add(60),
        }),
        [10; wire::encrypted_message::NONCE_SIZE],
    );

    let _outputs = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&ack_record)),
        &crypto_a,
    );

    let write = take_single_write(&mut a, &crypto_a);
    let (_, body) = decode_stream_body(&write.bytes, &session_key);
    assert!(matches!(
        body,
        StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq(3),
            frame: StreamFrame::Data(StreamFrameData {
                dir: Direction::Request,
                ..
            }),
            ..
        })
    ));

    let stream = a.streams.get(&stream_id).unwrap();
    let remaining: Vec<_> = stream
        .control()
        .in_flight
        .iter()
        .map(|(seq, _)| seq)
        .collect();
    assert_eq!(remaining, vec![StreamSeq(3)]);
    let frame = stream.control().in_flight.get(&StreamSeq(3)).unwrap();
    assert_eq!(frame.attempt, 1);
    assert!(matches!(frame.write_state, InFlightWriteState::Issued));
}

#[test]
fn fast_retransmit_respects_configured_threshold() {
    let crypto_a = TestCrypto::new(85);
    let crypto_b = TestCrypto::new(86);
    let session_key = SymmetricKey::from_data([10; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let peer_b = crypto_b.peer();
    let mut config = EngineConfig::default();
    config.stream_fast_retransmit_threshold = 3;
    let mut a = connected_engine_with_config(config, &crypto_a, peer_b, session_key.clone());

    let now = Instant::now();
    let stream_id = a
        .state
        .next_stream_id(StreamNamespace::for_local(crypto_a.xid(), crypto_b.xid()));
    insert_inflight_gap_stream(&mut a, stream_id, now);

    let ack_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &StreamBody::Ack(StreamAckBody {
            stream_id,
            ack: StreamAck {
                base: StreamSeq(2),
                bitmap: 0b0000_0110,
            },
            valid_until: wire::now_secs().saturating_add(60),
        }),
        [11; wire::encrypted_message::NONCE_SIZE],
    );

    let _outputs = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&ack_record)),
        &crypto_a,
    );

    if let Some(write) = a.take_next_write(&crypto_a) {
        let (_, body) = decode_stream_body(&write.bytes, &session_key);
        assert!(matches!(body, StreamBody::Ack(_)));
    }

    let stream = a.streams.get(&stream_id).unwrap();
    let remaining: Vec<_> = stream
        .control()
        .in_flight
        .iter()
        .map(|(seq, _)| seq)
        .collect();
    assert_eq!(remaining, vec![StreamSeq(3)]);
    let frame = stream.control().in_flight.get(&StreamSeq(3)).unwrap();
    assert_eq!(frame.attempt, 0);
    assert!(matches!(
        frame.write_state,
        InFlightWriteState::WaitingRetry { .. }
    ));
}

#[test]
fn timeout_retransmit_reuses_original_tx_seq_and_slot() {
    let config = EngineConfig::default();
    let crypto_a = TestCrypto::new(91);
    let crypto_b = TestCrypto::new(92);
    let peer_b = crypto_b.peer();
    let session_key = SymmetricKey::from_data([1; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let mut a = connected_engine(&crypto_a, peer_b, session_key.clone());

    let now = Instant::now();
    let _outputs_open = run_engine(
        &mut a,
        now,
        EngineInput::OpenStream {
            open_id: OpenId(44),
            request_head: b"open".to_vec(),
            request_prefix: None,
            config: StreamConfig::default(),
        },
        &crypto_a,
    );
    let write = take_single_write(&mut a, &crypto_a);
    let (_, initial_body) = decode_stream_body(&write.bytes, &session_key);
    assert!(matches!(
        &initial_body,
        StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq(1),
            frame: StreamFrame::Open(_),
            ..
        })
    ));
    let tracked_stream_id = match &initial_body {
        StreamBody::Message(StreamMessage {
            frame: StreamFrame::Open(StreamFrameOpen { stream_id, .. }),
            ..
        }) => *stream_id,
        _ => unreachable!(),
    };

    let _outputs_written = complete_engine_write(&mut a, write.id, Ok(()));

    let stream = a.streams.get(&tracked_stream_id).unwrap();
    assert_eq!(stream.control().in_flight.len(), 1);
    assert!(stream.control().in_flight.contains_key(&StreamSeq::START));
    assert_eq!(stream.control().next_tx_seq, StreamSeq(2));

    let _outputs_timeout = run_engine(
        &mut a,
        now + config.stream_ack_timeout,
        EngineInput::TimerExpired,
        &crypto_a,
    );
    let retransmit_write = take_single_write(&mut a, &crypto_a);
    let (_, retransmit_body) = decode_stream_body(&retransmit_write.bytes, &session_key);
    assert!(matches!(
        retransmit_body,
        StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq(1),
            frame: StreamFrame::Open(StreamFrameOpen { stream_id, .. }),
            ..
        }) if stream_id == tracked_stream_id
    ));

    let stream = a.streams.get(&tracked_stream_id).unwrap();
    assert_eq!(stream.control().in_flight.len(), 1);
    assert!(stream.control().in_flight.contains_key(&StreamSeq::START));
    assert_eq!(stream.control().next_tx_seq, StreamSeq(2));
    assert_eq!(
        stream
            .control()
            .in_flight
            .get(&StreamSeq::START)
            .unwrap()
            .attempt,
        1
    );
}

#[test]
fn take_next_write_drains_multiple_stream_frames_before_completion() {
    let crypto_a = TestCrypto::new(93);
    let crypto_b = TestCrypto::new(94);
    let session_key = SymmetricKey::from_data([12; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let peer_b = crypto_b.peer();
    let mut a = connected_engine(&crypto_a, peer_b, session_key.clone());

    let now = Instant::now();
    let stream_id = a
        .state
        .next_stream_id(StreamNamespace::for_local(crypto_a.xid(), crypto_b.xid()));
    insert_unwritten_inflight_stream_with_data(&mut a, stream_id, now, &[2, 3]);

    let writes = take_all_writes(&mut a, &crypto_a);
    assert_eq!(writes.len(), 3);

    let tx_seqs: Vec<_> = writes
        .iter()
        .map(
            |write| match decode_stream_body(&write.bytes, &session_key).1 {
                StreamBody::Message(message) => message.tx_seq,
                other => panic!("expected stream message, got {other:?}"),
            },
        )
        .collect();
    assert_eq!(tx_seqs, vec![StreamSeq::START, StreamSeq(2), StreamSeq(3)]);

    let unique_ids: std::collections::HashSet<_> = writes.iter().map(|write| write.id).collect();
    assert_eq!(unique_ids.len(), writes.len());
    assert_eq!(a.state.active_writes.len(), writes.len());
    assert!(a.take_next_write(&crypto_a).is_none());

    let stream = a.streams.get(&stream_id).unwrap();
    assert!(stream
        .control()
        .in_flight
        .iter()
        .all(|(_, in_flight)| matches!(in_flight.write_state, InFlightWriteState::Issued)));
}

#[test]
fn take_next_write_does_not_reissue_outstanding_frame() {
    let crypto_a = TestCrypto::new(95);
    let crypto_b = TestCrypto::new(96);
    let session_key = SymmetricKey::from_data([13; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let peer_b = crypto_b.peer();
    let mut a = connected_engine(&crypto_a, peer_b, session_key);

    let now = Instant::now();
    let stream_id = a
        .state
        .next_stream_id(StreamNamespace::for_local(crypto_a.xid(), crypto_b.xid()));
    insert_unwritten_inflight_stream_with_data(&mut a, stream_id, now, &[]);

    let write = take_single_write(&mut a, &crypto_a);
    assert!(a.take_next_write(&crypto_a).is_none());
    assert!(a.state.active_writes.contains_key(&write.id));
}

#[test]
fn take_next_write_round_robins_across_ready_streams() {
    let crypto_a = TestCrypto::new(97);
    let crypto_b = TestCrypto::new(98);
    let session_key = SymmetricKey::from_data([14; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let peer_b = crypto_b.peer();
    let mut a = connected_engine(&crypto_a, peer_b, session_key.clone());

    let now = Instant::now();
    let stream_id1 = a
        .state
        .next_stream_id(StreamNamespace::for_local(crypto_a.xid(), crypto_b.xid()));
    let stream_id2 = a
        .state
        .next_stream_id(StreamNamespace::for_local(crypto_a.xid(), crypto_b.xid()));
    insert_unwritten_inflight_stream_with_data(&mut a, stream_id1, now, &[2]);
    insert_unwritten_inflight_stream_with_data(&mut a, stream_id2, now, &[2]);

    let scheduled: Vec<_> = take_all_writes(&mut a, &crypto_a)
        .into_iter()
        .map(
            |write| match decode_stream_body(&write.bytes, &session_key).1 {
                StreamBody::Message(message) => (message.frame.stream_id(), message.tx_seq),
                other => panic!("expected stream message, got {other:?}"),
            },
        )
        .collect();

    assert_eq!(
        scheduled,
        vec![
            (stream_id1, StreamSeq::START),
            (stream_id2, StreamSeq::START),
            (stream_id1, StreamSeq(2)),
            (stream_id2, StreamSeq(2)),
        ]
    );
}

#[test]
fn stale_ack_delay_timer_after_piggyback_does_not_emit_extra_ack_only() {
    let mut harness = Harness::new(EngineConfig::default());

    harness.send_a(EngineInput::OpenStream {
        open_id: OpenId(30),
        request_head: b"open-head".to_vec(),
        request_prefix: None,
        config: StreamConfig::default(),
    });

    let _ = harness.drain_a();
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
        response_head: b"resp".to_vec(),
        response_prefix: None,
    });
    let _ = harness.drain_a();
    let _ = harness.drain_b();

    harness.now += EngineConfig::default().stream_ack_delay;
    harness.send_b(EngineInput::TimerExpired);
    let _outputs_b_timer = harness.drain_b();

    assert!(harness.b.take_next_write(&harness.crypto_b).is_none());
}

#[test]
fn provisional_timeout_after_late_open_is_ignored() {
    let config = EngineConfig::default();
    let crypto_a = TestCrypto::new(63);
    let crypto_b = TestCrypto::new(64);
    let session_key = SymmetricKey::from_data([11; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let peer_b = crypto_b.peer();
    let mut a = connected_engine_with_config(config, &crypto_a, peer_b, session_key.clone());

    let now = Instant::now();
    let stream_id = StreamId(StreamNamespace::for_local(crypto_b.xid(), crypto_a.xid()).bit() | 1);

    let early_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq(2),
            ack: None,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Data(StreamFrameData {
                stream_id,
                dir: Direction::Request,
                chunk: BodyChunk {
                    bytes: b"hello".to_vec(),
                    fin: false,
                },
            }),
        }),
        [31; wire::encrypted_message::NONCE_SIZE],
    );
    let _ = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&early_record)),
        &crypto_a,
    );

    let open_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq::START,
            ack: None,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Open(StreamFrameOpen {
                stream_id,
                request_head: b"late-open".to_vec(),
                request_prefix: None,
            }),
        }),
        [32; wire::encrypted_message::NONCE_SIZE],
    );
    let outputs_open = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&open_record)),
        &crypto_a,
    );
    assert!(outputs_open.iter().any(|output| matches!(
        output,
        EngineOutput::InboundStreamOpened { stream_id: id, .. } if *id == stream_id
    )));

    let _outputs_timeout = run_engine(
        &mut a,
        now + config.default_open_timeout,
        EngineInput::TimerExpired,
        &crypto_a,
    );

    assert!(matches!(
        a.streams.get(&stream_id),
        Some(StreamState::Responder(_))
    ));
    if let Some(write) = a.take_next_write(&crypto_a) {
        let (_, body) = decode_stream_body(&write.bytes, &session_key);
        assert!(!matches!(
            body,
            StreamBody::Message(StreamMessage {
                frame: StreamFrame::Reset(_),
                ..
            })
        ));
    }
}

#[test]
fn ack_only_write_failure_immediately_requeues_ack_without_spending_extra_seq() {
    let config = EngineConfig::default();
    let crypto_a = TestCrypto::new(65);
    let crypto_b = TestCrypto::new(66);
    let session_key = SymmetricKey::from_data([12; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let peer_b = crypto_b.peer();
    let mut a = connected_engine_with_config(config, &crypto_a, peer_b, session_key.clone());

    let now = Instant::now();
    let stream_id = StreamId(StreamNamespace::for_local(crypto_b.xid(), crypto_a.xid()).bit() | 1);
    let open_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq::START,
            ack: None,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Open(StreamFrameOpen {
                stream_id,
                request_head: b"open".to_vec(),
                request_prefix: None,
            }),
        }),
        [33; wire::encrypted_message::NONCE_SIZE],
    );
    let outputs_open = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&open_record)),
        &crypto_a,
    );
    assert!(outputs_open.iter().any(|output| matches!(
        output,
        EngineOutput::InboundStreamOpened { stream_id: id, .. } if *id == stream_id
    )));

    let _outputs_ack = run_engine(
        &mut a,
        now + config.stream_ack_delay,
        EngineInput::TimerExpired,
        &crypto_a,
    );
    let ack_write = take_single_write(&mut a, &crypto_a);
    let (_, ack_body) = decode_stream_body(&ack_write.bytes, &session_key);
    assert!(matches!(
        ack_body,
        StreamBody::Ack(StreamAckBody {
            stream_id: id,
            ack: StreamAck {
                base: StreamSeq::START,
                bitmap: 0,
            },
            ..
        }) if id == stream_id
    ));

    let outputs_failed = complete_engine_write(&mut a, ack_write.id, Err(QlError::SendFailed));
    assert!(!outputs_failed.iter().any(|output| matches!(
        output,
        EngineOutput::StreamReaped { .. } | EngineOutput::OpenFailed { .. }
    )));
    let retry_write = take_single_write(&mut a, &crypto_a);
    let (_, retry_body) = decode_stream_body(&retry_write.bytes, &session_key);
    assert!(matches!(
        retry_body,
        StreamBody::Ack(StreamAckBody {
            stream_id: id,
            ack: StreamAck {
                base: StreamSeq::START,
                bitmap: 0,
            },
            ..
        }) if id == stream_id
    ));

    let _ = complete_engine_write(&mut a, retry_write.id, Ok(()));

    let _outputs_accept = run_engine(
        &mut a,
        now + config.stream_ack_delay,
        EngineInput::AcceptStream {
            stream_id,
            response_head: b"resp".to_vec(),
            response_prefix: None,
        },
        &crypto_a,
    );
    let accept_write = take_single_write(&mut a, &crypto_a);
    let (_, body) = decode_stream_body(&accept_write.bytes, &session_key);
    assert!(matches!(
        body,
        StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq::START,
            frame: StreamFrame::Accept(StreamFrameAccept { stream_id: id, .. }),
            ..
        }) if id == stream_id
    ));
    let stream = a.streams.get(&stream_id).unwrap();
    assert_eq!(stream.control().next_tx_seq, StreamSeq(2));
}

#[test]
fn duplicate_committed_data_is_acked_without_redelivery() {
    let config = EngineConfig::default();
    let crypto_a = TestCrypto::new(67);
    let crypto_b = TestCrypto::new(68);
    let session_key = SymmetricKey::from_data([13; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let peer_b = crypto_b.peer();
    let mut a = connected_engine_with_config(config, &crypto_a, peer_b, session_key.clone());

    let now = Instant::now();
    let stream_id = StreamId(StreamNamespace::for_local(crypto_b.xid(), crypto_a.xid()).bit() | 1);

    for (nonce, body) in [
        (
            34u8,
            StreamBody::Message(StreamMessage {
                tx_seq: StreamSeq::START,
                ack: None,
                valid_until: wire::now_secs().saturating_add(60),
                frame: StreamFrame::Open(StreamFrameOpen {
                    stream_id,
                    request_head: b"open".to_vec(),
                    request_prefix: None,
                }),
            }),
        ),
        (
            35u8,
            StreamBody::Message(StreamMessage {
                tx_seq: StreamSeq(2),
                ack: None,
                valid_until: wire::now_secs().saturating_add(60),
                frame: StreamFrame::Data(StreamFrameData {
                    stream_id,
                    dir: Direction::Request,
                    chunk: BodyChunk {
                        bytes: b"hello".to_vec(),
                        fin: false,
                    },
                }),
            }),
        ),
    ] {
        let record = wire::stream::encrypt_stream(
            QlHeader {
                sender: crypto_b.xid(),
                recipient: crypto_a.xid(),
            },
            &session_key,
            &body,
            [nonce; wire::encrypted_message::NONCE_SIZE],
        );
        let _ = run_engine(
            &mut a,
            now,
            EngineInput::Incoming(wire::encode_record(&record)),
            &crypto_a,
        );
    }

    let duplicate_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq(2),
            ack: None,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Data(StreamFrameData {
                stream_id,
                dir: Direction::Request,
                chunk: BodyChunk {
                    bytes: b"hello".to_vec(),
                    fin: false,
                },
            }),
        }),
        [36; wire::encrypted_message::NONCE_SIZE],
    );
    let outputs_dup = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&duplicate_record)),
        &crypto_a,
    );

    assert!(!outputs_dup
        .iter()
        .any(|output| matches!(output, EngineOutput::InboundData { .. })));
    let ack_write = take_single_write(&mut a, &crypto_a);
    let (_, body) = decode_stream_body(&ack_write.bytes, &session_key);
    assert!(matches!(
        body,
        StreamBody::Ack(StreamAckBody {
            stream_id: id,
            ack: StreamAck {
                base: StreamSeq(2),
                bitmap: 0,
            },
            ..
        }) if id == stream_id
    ));
}

#[test]
fn repeated_identical_gap_ack_only_fast_retransmits_once() {
    let crypto_a = TestCrypto::new(69);
    let crypto_b = TestCrypto::new(70);
    let session_key = SymmetricKey::from_data([14; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let peer_b = crypto_b.peer();
    let mut config = EngineConfig::default();
    config.stream_fast_retransmit_threshold = 2;
    let mut a = connected_engine_with_config(config, &crypto_a, peer_b, session_key.clone());

    let now = Instant::now();
    let stream_id = a
        .state
        .next_stream_id(StreamNamespace::for_local(crypto_a.xid(), crypto_b.xid()));
    insert_inflight_gap_stream(&mut a, stream_id, now);

    let ack_record = |nonce: u8| {
        wire::stream::encrypt_stream(
            QlHeader {
                sender: crypto_b.xid(),
                recipient: crypto_a.xid(),
            },
            &session_key,
            &StreamBody::Ack(StreamAckBody {
                stream_id,
                ack: StreamAck {
                    base: StreamSeq(2),
                    bitmap: 0b0000_0110,
                },
                valid_until: wire::now_secs().saturating_add(60),
            }),
            [nonce; wire::encrypted_message::NONCE_SIZE],
        )
    };

    let _outputs_first = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&ack_record(37))),
        &crypto_a,
    );
    let write = take_single_write(&mut a, &crypto_a);
    let (_, body) = decode_stream_body(&write.bytes, &session_key);
    assert!(matches!(
        body,
        StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq(3),
            ..
        })
    ));

    let _ = complete_engine_write(&mut a, write.id, Ok(()));

    let _outputs_second = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&ack_record(38))),
        &crypto_a,
    );
    assert!(a.take_next_write(&crypto_a).is_none());
}

#[test]
fn fast_recovery_clears_after_gap_is_acked_and_allows_next_gap() {
    let crypto_a = TestCrypto::new(73);
    let crypto_b = TestCrypto::new(74);
    let session_key = SymmetricKey::from_data([15; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let peer_b = crypto_b.peer();
    let mut config = EngineConfig::default();
    config.stream_fast_retransmit_threshold = 1;
    let mut a = connected_engine_with_config(config, &crypto_a, peer_b, session_key.clone());

    let now = Instant::now();
    let stream_id = a
        .state
        .next_stream_id(StreamNamespace::for_local(crypto_a.xid(), crypto_b.xid()));
    insert_inflight_stream_with_data(&mut a, stream_id, now, &[2, 3, 4, 5, 6]);

    let first_ack = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &StreamBody::Ack(StreamAckBody {
            stream_id,
            ack: StreamAck {
                base: StreamSeq(2),
                bitmap: 0b0000_0010,
            },
            valid_until: wire::now_secs().saturating_add(60),
        }),
        [39; wire::encrypted_message::NONCE_SIZE],
    );
    let _outputs_first = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&first_ack)),
        &crypto_a,
    );
    let write_first = take_single_write(&mut a, &crypto_a);
    let (_, first_body) = decode_stream_body(&write_first.bytes, &session_key);
    assert!(matches!(
        first_body,
        StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq(3),
            ..
        })
    ));

    let _ = complete_engine_write(&mut a, write_first.id, Ok(()));

    let second_ack = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &StreamBody::Ack(StreamAckBody {
            stream_id,
            ack: StreamAck {
                base: StreamSeq(4),
                bitmap: 0b0000_0010,
            },
            valid_until: wire::now_secs().saturating_add(60),
        }),
        [40; wire::encrypted_message::NONCE_SIZE],
    );
    let _outputs_second = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&second_ack)),
        &crypto_a,
    );
    let write_second = take_single_write(&mut a, &crypto_a);
    let (_, second_body) = decode_stream_body(&write_second.bytes, &session_key);
    assert!(matches!(
        second_body,
        StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq(5),
            ..
        })
    ));
}

#[test]
fn fast_retransmit_and_retry_deadline_same_tick_only_send_once() {
    let crypto_a = TestCrypto::new(75);
    let crypto_b = TestCrypto::new(76);
    let session_key = SymmetricKey::from_data([16; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let peer_b = crypto_b.peer();
    let mut config = EngineConfig::default();
    config.stream_fast_retransmit_threshold = 2;
    let mut a = connected_engine_with_config(config, &crypto_a, peer_b, session_key.clone());

    let now = Instant::now();
    let stream_id = a
        .state
        .next_stream_id(StreamNamespace::for_local(crypto_a.xid(), crypto_b.xid()));
    insert_inflight_gap_stream(&mut a, stream_id, now);
    a.streams
        .get_mut(&stream_id)
        .unwrap()
        .control_mut()
        .set_retry_deadline(StreamSeq(3), now);

    let ack_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        &StreamBody::Ack(StreamAckBody {
            stream_id,
            ack: StreamAck {
                base: StreamSeq(2),
                bitmap: 0b0000_0110,
            },
            valid_until: wire::now_secs().saturating_add(60),
        }),
        [41; wire::encrypted_message::NONCE_SIZE],
    );
    let _outputs_ack = run_engine(
        &mut a,
        now,
        EngineInput::Incoming(wire::encode_record(&ack_record)),
        &crypto_a,
    );
    let _write = take_single_write(&mut a, &crypto_a);
    assert!(a.take_next_write(&crypto_a).is_none());

    let _outputs_timeout = run_engine(&mut a, now, EngineInput::TimerExpired, &crypto_a);
    assert!(a.take_next_write(&crypto_a).is_none());
}

#[test]
fn replayed_heartbeat_is_ignored() {
    let crypto_a = TestCrypto::new(101);
    let crypto_b = TestCrypto::new(102);
    let session_key = SymmetricKey::from_data([4; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let peer_b = crypto_b.peer();
    let mut a = connected_engine(&crypto_a, peer_b, session_key.clone());
    let now = Instant::now();
    let heartbeat = wire::heartbeat::encrypt_heartbeat(
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        &session_key,
        wire::heartbeat::HeartbeatBody {
            meta: wire::ControlMeta {
                packet_id: PacketId(7),
                valid_until: wire::now_secs().saturating_add(60),
            },
        },
        [3; wire::encrypted_message::NONCE_SIZE],
    );
    let bytes = wire::encode_record(&heartbeat);

    let _first = run_engine(&mut a, now, EngineInput::Incoming(bytes.clone()), &crypto_a);
    let first_write = take_single_write(&mut a, &crypto_a);
    let first_record = wire::decode_record(&first_write.bytes).unwrap();
    assert!(matches!(first_record.payload, QlPayload::Heartbeat(_)));
    let _ = complete_engine_write(&mut a, first_write.id, Ok(()));

    let _second = run_engine(&mut a, now, EngineInput::Incoming(bytes), &crypto_a);
    assert!(a.take_next_write(&crypto_a).is_none());
}

#[test]
fn replayed_unpair_is_ignored_after_rebind() {
    let config = EngineConfig::default();
    let crypto_a = TestCrypto::new(111);
    let crypto_b = TestCrypto::new(112);
    let peer_b = crypto_b.peer();
    let session_key = SymmetricKey::from_data([5; SymmetricKey::SYMMETRIC_KEY_SIZE]);
    let mut a = Engine::new(config, crypto_a.identity.clone(), Some(peer_b.clone()));
    a.peer.as_mut().unwrap().session = PeerSession::Connected {
        session_key,
        keepalive: KeepAliveState::default(),
    };
    let now = Instant::now();
    let bytes = wire::encode_record(&wire::unpair::build_unpair_record(
        &crypto_b.identity,
        QlHeader {
            sender: crypto_b.xid(),
            recipient: crypto_a.xid(),
        },
        wire::ControlMeta {
            packet_id: PacketId(9),
            valid_until: wire::now_secs().saturating_add(60),
        },
    ));

    let first = run_engine(&mut a, now, EngineInput::Incoming(bytes.clone()), &crypto_a);
    assert!(first
        .iter()
        .any(|output| matches!(output, EngineOutput::ClearPeer)));
    assert!(a.peer.is_none());

    let _ = run_engine(
        &mut a,
        now,
        EngineInput::BindPeer(peer_b.clone()),
        &crypto_a,
    );
    assert!(a.peer.is_some());

    let second = run_engine(&mut a, now, EngineInput::Incoming(bytes), &crypto_a);
    assert!(!second
        .iter()
        .any(|output| matches!(output, EngineOutput::ClearPeer)));
    assert_eq!(
        a.peer.as_ref().map(|peer| peer.peer),
        Some(peer_b.peer)
    );
}
