use std::{
    cell::Cell,
    mem,
    ops::{Deref, DerefMut},
    time::{Duration, Instant},
};

use bc_components::{MLDSA, MLKEM, SymmetricKey, XID};

use crate::{
    PacketId, Peer,
    engine::{state::StreamNamespace, stream::*, *},
    identity::QlIdentity,
    wire::{self, QlHeader, QlPayload, QlRecord, StreamSeq, stream::*},
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
        };
        b.peer.as_mut().unwrap().session = PeerSession::Connected {
            session_key,
            keepalive: KeepAliveState::default(),
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
        meta: StreamMeta {
            stream_id,
            last_activity: now,
        },
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
    engine.streams.insert(stream_id, stream);
}

fn insert_inflight_stream_with_data(
    engine: &mut EngineWrapper,
    stream_id: StreamId,
    now: Instant,
    data_seqs: &[u32],
) {
    let retry_at = now + Duration::from_secs(60);
    let mut stream = StreamState {
        meta: StreamMeta {
            stream_id,
            last_activity: now,
        },
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
    engine.streams.insert(stream_id, stream);
}

fn insert_unwritten_inflight_stream_with_data(
    engine: &mut EngineWrapper,
    stream_id: StreamId,
    now: Instant,
    data_seqs: &[u32],
) {
    let mut stream = StreamState {
        meta: StreamMeta {
            stream_id,
            last_activity: now,
        },
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
    engine.streams.insert(stream_id, stream);
}

#[test]
fn simultaneous_opens_use_disjoint_stream_id_namespaces() {
    let config = EngineConfig::default();
    let mut harness = Harness::connected(config);
    let now = harness.now;

    let stream_id_a = harness
        .a
        .open_stream(now, b"a-open".to_vec(), None, StreamConfig::default())
        .unwrap();
    let stream_id_b = harness
        .b
        .open_stream(now, b"b-open".to_vec(), None, StreamConfig::default())
        .unwrap();

    assert_ne!(stream_id_a, stream_id_b);
    assert!(
        StreamNamespace::for_local(harness.a.engine.identity.xid, harness.b.engine.identity.xid)
            .matches(stream_id_a)
    );
    assert!(
        StreamNamespace::for_local(harness.b.engine.identity.xid, harness.a.engine.identity.xid)
            .matches(stream_id_b)
    );

    let write_a = harness.a.take_next_write().unwrap();
    let write_b = harness.b.take_next_write().unwrap();

    let _ = harness.a.complete_write_collect(write_a.id, Ok(()));
    let _ = harness.b.complete_write_collect(write_b.id, Ok(()));

    let outputs_a_incoming = harness
        .a
        .run_tick_collect(now, EngineInput::Incoming(write_b.bytes));
    let outputs_b_incoming = harness
        .b
        .run_tick_collect(now, EngineInput::Incoming(write_a.bytes));

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
    assert_eq!(harness.a.streams.len(), 2);
    assert_eq!(harness.b.streams.len(), 2);
}

#[test]
fn invalid_future_frame_does_not_ack_outstanding_open() {
    let config = EngineConfig::default();
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(config, 31, 5);
    let stream_id = engine
        .open_stream(now, b"open".to_vec(), None, StreamConfig::default())
        .unwrap();

    let message = StreamMessage {
        tx_seq: StreamSeq(2),
        ack: crate::wire::stream::StreamAck {
            base: StreamSeq(0),
            bitmap: 0,
        },
        valid_until: wire::now_secs().saturating_add(60),
        frame: StreamFrame::Data(StreamFrameData {
            stream_id,
            chunk: BodyChunk {
                bytes: b"resp".to_vec(),
                fin: false,
            },
        }),
    };

    let body = StreamBody::Message(message);
    let record = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
        },
        &session_key,
        &body,
        [9; wire::encrypted_message::NONCE_SIZE],
    );

    let outputs_incoming =
        engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&record)));

    assert!(
        !outputs_incoming
            .iter()
            .any(|output| matches!(output, EngineOutput::InboundData { .. }))
    );

    let stream = engine.streams.get(&stream_id).unwrap();
    assert!(stream.control.in_flight.contains_key(&StreamSeq::START));
}

#[test]
fn ack_for_issued_open_is_applied_before_write_completion() {
    let config = EngineConfig::default();
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(config, 33, 7);
    let stream_id = engine
        .open_stream(now, b"open".to_vec(), None, StreamConfig::default())
        .unwrap();

    let _open_write = engine.take_next_write().unwrap();

    let message = StreamMessage {
        tx_seq: StreamSeq::START,
        ack: StreamAck {
            base: StreamSeq::START,
            bitmap: 0,
        },
        valid_until: wire::now_secs().saturating_add(60),
        frame: StreamFrame::Data(StreamFrameData {
            stream_id,
            chunk: BodyChunk {
                bytes: b"resp".to_vec(),
                fin: false,
            },
        }),
    };
    let record = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
        },
        &session_key,
        &StreamBody::Message(message),
        [10; wire::encrypted_message::NONCE_SIZE],
    );

    let outputs_incoming =
        engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&record)));

    assert!(outputs_incoming.iter().any(|output| matches!(
        output,
        EngineOutput::InboundData {
            stream_id: id,
            bytes,
        } if *id == stream_id && bytes == b"resp"
    )));
    let stream = engine.streams.get(&stream_id).unwrap();
    assert!(!stream.control.in_flight.contains_key(&StreamSeq::START));
}

#[test]
fn ack_does_not_retire_ready_data() {
    let config = EngineConfig::default();
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(config, 35, 8);
    let stream_id = engine
        .open_stream(now, b"open".to_vec(), None, StreamConfig::default())
        .unwrap();

    let _open_write = engine.take_next_write().unwrap();
    let _ = engine.run_tick_collect(
        now,
        EngineInput::OutboundData {
            stream_id,
            bytes: b"body".to_vec(),
        },
    );

    let message = StreamMessage {
        tx_seq: StreamSeq::START,
        ack: StreamAck {
            base: StreamSeq(2),
            bitmap: 0,
        },
        valid_until: wire::now_secs().saturating_add(60),
        frame: StreamFrame::Data(StreamFrameData {
            stream_id,
            chunk: BodyChunk {
                bytes: b"resp".to_vec(),
                fin: false,
            },
        }),
    };
    let record = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
        },
        &session_key,
        &StreamBody::Message(message),
        [11; wire::encrypted_message::NONCE_SIZE],
    );

    let outputs_incoming =
        engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&record)));

    assert!(outputs_incoming.iter().any(|output| matches!(
        output,
        EngineOutput::InboundData {
            stream_id: id,
            bytes,
        } if *id == stream_id && bytes == b"resp"
    )));

    let stream = engine.streams.get(&stream_id).unwrap();
    assert!(!stream.control.in_flight.contains_key(&StreamSeq::START));
    assert!(stream.control.in_flight.contains_key(&StreamSeq(2)));

    let write = engine.take_next_write().unwrap();
    let (_, body) = decode_stream_body(&write.bytes, &session_key);
    assert!(matches!(
        body,
        StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq(2),
            frame: StreamFrame::Data(StreamFrameData {
                stream_id: id,
                chunk: BodyChunk { bytes, fin: false },
            }),
            ..
        }) if id == stream_id && bytes == b"body"
    ));
}

#[test]
fn late_failed_write_after_remote_close_ack_is_ignored() {
    let config = EngineConfig::default();
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(config, 37, 9);
    let stream_id = engine
        .open_stream(now, b"open".to_vec(), None, StreamConfig::default())
        .unwrap();

    let open_write = engine.take_next_write().unwrap();

    let record = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
        },
        &session_key,
        &StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq::START,
            ack: StreamAck {
                base: StreamSeq::START,
                bitmap: 0,
            },
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Close(StreamFrameClose {
                stream_id,
                target: CloseTarget::Both,
                code: CloseCode::PROTOCOL,
                payload: Vec::new(),
            }),
        }),
        [12; wire::encrypted_message::NONCE_SIZE],
    );

    let outputs_close =
        engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&record)));

    assert!(outputs_close.iter().any(|output| matches!(
        output,
        EngineOutput::OutboundFailed {
            stream_id: id,
            error: QlError::StreamClosed {
                target: CloseTarget::Both,
                code: CloseCode::PROTOCOL,
                payload,
            },
        } if *id == stream_id
            && payload.is_empty()
    )));
    assert!(outputs_close.iter().any(|output| matches!(
        output,
        EngineOutput::InboundFailed {
            stream_id: id,
            error: QlError::StreamClosed {
                target: CloseTarget::Both,
                code: CloseCode::PROTOCOL,
                payload,
            },
        } if *id == stream_id
            && payload.is_empty()
    )));
    let stream = engine.streams.get(&stream_id).unwrap();
    assert!(!stream.control.in_flight.contains_key(&StreamSeq::START));

    let outputs_late = engine.complete_write_collect(open_write.id, Err(QlError::SendFailed));
    assert!(outputs_late.is_empty());
    assert!(engine.streams.contains_key(&stream_id));
}

#[test]
fn local_close_both_is_idempotent() {
    let SingleEngineHarness {
        now,
        mut engine,
        session_key,
        ..
    } = SingleEngineHarness::connected(EngineConfig::default(), 39, 10);
    let stream_id = engine
        .open_stream(now, b"open".to_vec(), None, StreamConfig::default())
        .unwrap();

    let open_write = engine.take_next_write().unwrap();
    let _ = engine.complete_write_collect(open_write.id, Ok(()));

    let _ = engine.run_tick_collect(
        now,
        EngineInput::CloseStream {
            stream_id,
            target: CloseTarget::Request,
            code: CloseCode::CANCELLED,
            payload: Vec::new(),
        },
    );
    let request_close = engine.take_next_write().unwrap();
    let (_, request_close_body) = decode_stream_body(&request_close.bytes, &session_key);
    assert!(matches!(
        request_close_body,
        StreamBody::Message(StreamMessage {
            frame: StreamFrame::Close(StreamFrameClose {
                stream_id: id,
                target: CloseTarget::Request,
                ..
            }),
            ..
        }) if id == stream_id
    ));
    let _ = engine.complete_write_collect(request_close.id, Ok(()));

    let _ = engine.run_tick_collect(
        now,
        EngineInput::CloseStream {
            stream_id,
            target: CloseTarget::Both,
            code: CloseCode::CANCELLED,
            payload: Vec::new(),
        },
    );
    let both_close = engine.take_next_write().unwrap();
    let (_, both_close_body) = decode_stream_body(&both_close.bytes, &session_key);
    assert!(matches!(
        both_close_body,
        StreamBody::Message(StreamMessage {
            frame: StreamFrame::Close(StreamFrameClose {
                stream_id: id,
                target: CloseTarget::Both,
                ..
            }),
            ..
        }) if id == stream_id
    ));
    let _ = engine.complete_write_collect(both_close.id, Ok(()));

    let _ = engine.run_tick_collect(
        now,
        EngineInput::CloseStream {
            stream_id,
            target: CloseTarget::Both,
            code: CloseCode::CANCELLED,
            payload: Vec::new(),
        },
    );
    assert!(engine.take_next_write().is_none());
}

#[test]
fn out_of_order_remote_stream_buffers_until_open_arrives() {
    let config = EngineConfig::default();
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(config, 41, 6);
    let stream_id =
        StreamId(StreamNamespace::for_local(peer.xid, engine.engine.identity.xid).bit() | 1);

    let data_message = StreamMessage {
        tx_seq: StreamSeq(2),
        ack: StreamAck::EMPTY,
        valid_until: wire::now_secs().saturating_add(60),
        frame: StreamFrame::Data(crate::wire::stream::StreamFrameData {
            stream_id,
            chunk: BodyChunk {
                bytes: b"hello".to_vec(),
                fin: false,
            },
        }),
    };
    let data_body = StreamBody::Message(data_message);
    let data_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
        },
        &session_key,
        &data_body,
        [11; wire::encrypted_message::NONCE_SIZE],
    );

    let outputs_data = engine.run_tick_collect(
        now,
        EngineInput::Incoming(wire::encode_record(&data_record)),
    );

    assert!(
        !outputs_data
            .iter()
            .any(|output| matches!(output, EngineOutput::InboundStreamOpened { .. }))
    );
    assert!(
        !outputs_data
            .iter()
            .any(|output| matches!(output, EngineOutput::InboundData { .. }))
    );
    assert!(engine.take_next_write().is_some());
    assert!(
        engine
            .streams
            .get(&stream_id)
            .is_some_and(StreamState::is_provisional)
    );

    let open_message = StreamMessage {
        tx_seq: StreamSeq(1),
        ack: StreamAck::EMPTY,
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
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
        },
        &session_key,
        &open_body,
        [12; wire::encrypted_message::NONCE_SIZE],
    );

    let outputs_open = engine.run_tick_collect(
        now,
        EngineInput::Incoming(wire::encode_record(&open_record)),
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
            bytes,
        } if *id == stream_id && bytes == b"hello"
    )));
}

#[test]
fn delayed_ack_only_does_not_consume_sequence_space() {
    let mut harness = Harness::connected(EngineConfig::default());
    let stream_id = harness
        .a
        .open_stream(
            harness.now,
            b"open-head".to_vec(),
            None,
            StreamConfig::default(),
        )
        .unwrap();
    let open_write = harness.a.take_next_write().unwrap();
    harness.complete_side_write(Side::A, open_write.id, Ok(()));
    harness.run_side(Side::B, EngineInput::Incoming(open_write.bytes));

    harness.now += EngineConfig::default().stream_ack_delay;
    harness.run_side(Side::B, EngineInput::TimerExpired);

    let _outputs_b = harness.b.drain_outputs();

    let stream = harness.b.streams.get(&stream_id).unwrap();
    assert!(stream.control.in_flight.is_empty());
    assert_eq!(stream.control.next_tx_seq, StreamSeq::START);
}

#[test]
fn half_window_progress_flushes_ack_before_timer() {
    let config = EngineConfig::default();
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(config, 61, 8);
    let stream_id =
        StreamId(StreamNamespace::for_local(peer.xid, engine.engine.identity.xid).bit() | 1);
    let messages = [
        StreamMessage {
            tx_seq: StreamSeq(1),
            ack: StreamAck::EMPTY,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Open(crate::wire::stream::StreamFrameOpen {
                stream_id,
                request_head: b"open".to_vec(),
                request_prefix: None,
            }),
        },
        StreamMessage {
            tx_seq: StreamSeq(2),
            ack: StreamAck::EMPTY,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Data(crate::wire::stream::StreamFrameData {
                stream_id,
                chunk: BodyChunk {
                    bytes: b"a".to_vec(),
                    fin: false,
                },
            }),
        },
        StreamMessage {
            tx_seq: StreamSeq(3),
            ack: StreamAck::EMPTY,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Data(crate::wire::stream::StreamFrameData {
                stream_id,
                chunk: BodyChunk {
                    bytes: b"b".to_vec(),
                    fin: false,
                },
            }),
        },
        StreamMessage {
            tx_seq: StreamSeq(4),
            ack: StreamAck::EMPTY,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Data(crate::wire::stream::StreamFrameData {
                stream_id,
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
                sender: peer.xid,
                recipient: engine.engine.identity.xid,
            },
            &session_key,
            &body,
            [message.tx_seq.0 as u8; wire::encrypted_message::NONCE_SIZE],
        );
        let _outputs =
            engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&record)));
        assert!(engine.take_next_write().is_none());
    }

    let body = StreamBody::Message(messages[3].clone());
    let record = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
        },
        &session_key,
        &body,
        [4; wire::encrypted_message::NONCE_SIZE],
    );
    let _outputs =
        engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&record)));

    let ack_write = engine.take_next_write().unwrap();
    let (_, ack_body) = decode_stream_body(&ack_write.bytes, &session_key);
    assert!(matches!(ack_body, StreamBody::Ack(_)));
}

#[test]
fn out_of_order_loss_reports_selective_ack_bitmap() {
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(EngineConfig::default(), 71, 3);
    let stream_id =
        StreamId(StreamNamespace::for_local(peer.xid, engine.engine.identity.xid).bit() | 1);
    let messages = [
        StreamMessage {
            tx_seq: StreamSeq(1),
            ack: StreamAck::EMPTY,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Open(StreamFrameOpen {
                stream_id,
                request_head: b"open".to_vec(),
                request_prefix: None,
            }),
        },
        StreamMessage {
            tx_seq: StreamSeq(2),
            ack: StreamAck::EMPTY,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Data(StreamFrameData {
                stream_id,
                chunk: BodyChunk {
                    bytes: b"a".to_vec(),
                    fin: false,
                },
            }),
        },
        StreamMessage {
            tx_seq: StreamSeq(4),
            ack: StreamAck::EMPTY,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Data(StreamFrameData {
                stream_id,
                chunk: BodyChunk {
                    bytes: b"c".to_vec(),
                    fin: false,
                },
            }),
        },
        StreamMessage {
            tx_seq: StreamSeq(5),
            ack: StreamAck::EMPTY,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Data(StreamFrameData {
                stream_id,
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
                sender: peer.xid,
                recipient: engine.engine.identity.xid,
            },
            &session_key,
            &StreamBody::Message(message.clone()),
            [message.tx_seq.0 as u8; wire::encrypted_message::NONCE_SIZE],
        );
        let _outputs =
            engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&record)));
        assert!(engine.take_next_write().is_none());
    }

    let record4 = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
        },
        &session_key,
        &StreamBody::Message(messages[2].clone()),
        [4; wire::encrypted_message::NONCE_SIZE],
    );
    let outputs4 =
        engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&record4)));
    let ack_write4 = engine.take_next_write().unwrap();
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
    assert!(
        !outputs4
            .iter()
            .any(|output| matches!(output, EngineOutput::InboundData { .. }))
    );
    let _ = engine.complete_write_collect(ack_write4.id, Ok(()));

    let record5 = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
        },
        &session_key,
        &StreamBody::Message(messages[3].clone()),
        [5; wire::encrypted_message::NONCE_SIZE],
    );
    let outputs5 =
        engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&record5)));
    let ack_write5 = engine.take_next_write().unwrap();
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
    assert!(
        !outputs5
            .iter()
            .any(|output| matches!(output, EngineOutput::InboundData { .. }))
    );
}

#[test]
fn selective_ack_only_body_retires_acked_gap_tail() {
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(EngineConfig::default(), 81, 2);
    let stream_id = engine.state.next_stream_id(StreamNamespace::for_local(
        engine.engine.identity.xid,
        peer.xid,
    ));
    insert_inflight_gap_stream(&mut engine, stream_id, now);

    let ack_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
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

    let outputs =
        engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&ack_record)));

    assert!(
        !outputs
            .iter()
            .any(|output| matches!(output, EngineOutput::OutboundFailed { .. }))
    );
    let stream = engine.streams.get(&stream_id).unwrap();
    let remaining: Vec<_> = stream
        .control
        .in_flight
        .iter()
        .map(|(seq, _)| seq)
        .collect();
    assert_eq!(remaining, vec![StreamSeq(3)]);
    assert_eq!(stream.control.next_tx_seq, StreamSeq(6));
}

#[test]
fn fast_retransmit_resends_oldest_gap_when_threshold_met() {
    let mut config = EngineConfig::default();
    config.stream_fast_retransmit_threshold = 2;
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(config, 83, 9);
    let stream_id = engine.state.next_stream_id(StreamNamespace::for_local(
        engine.engine.identity.xid,
        peer.xid,
    ));
    insert_inflight_gap_stream(&mut engine, stream_id, now);

    let ack_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
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

    let _outputs =
        engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&ack_record)));

    let write = engine.take_next_write().unwrap();
    let (_, body) = decode_stream_body(&write.bytes, &session_key);
    assert!(matches!(
        body,
        StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq(3),
            frame: StreamFrame::Data(StreamFrameData { .. }),
            ..
        })
    ));

    let stream = engine.streams.get(&stream_id).unwrap();
    let remaining: Vec<_> = stream
        .control
        .in_flight
        .iter()
        .map(|(seq, _)| seq)
        .collect();
    assert_eq!(remaining, vec![StreamSeq(3)]);
    let frame = stream.control.in_flight.get(&StreamSeq(3)).unwrap();
    assert_eq!(frame.attempt, 1);
    assert!(matches!(frame.write_state, InFlightWriteState::Issued));
}

#[test]
fn fast_retransmit_respects_configured_threshold() {
    let mut config = EngineConfig::default();
    config.stream_fast_retransmit_threshold = 3;
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(config, 85, 10);
    let stream_id = engine.state.next_stream_id(StreamNamespace::for_local(
        engine.engine.identity.xid,
        peer.xid,
    ));
    insert_inflight_gap_stream(&mut engine, stream_id, now);

    let ack_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
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

    let _outputs =
        engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&ack_record)));

    if let Some(write) = engine.take_next_write() {
        let (_, body) = decode_stream_body(&write.bytes, &session_key);
        assert!(matches!(body, StreamBody::Ack(_)));
    }

    let stream = engine.streams.get(&stream_id).unwrap();
    let remaining: Vec<_> = stream
        .control
        .in_flight
        .iter()
        .map(|(seq, _)| seq)
        .collect();
    assert_eq!(remaining, vec![StreamSeq(3)]);
    let frame = stream.control.in_flight.get(&StreamSeq(3)).unwrap();
    assert_eq!(frame.attempt, 0);
    assert!(matches!(
        frame.write_state,
        InFlightWriteState::WaitingRetry { .. }
    ));
}

#[test]
fn timeout_retransmit_reuses_original_tx_seq_and_slot() {
    let config = EngineConfig::default();
    let SingleEngineHarness {
        now,
        mut engine,
        peer: _,
        session_key,
    } = SingleEngineHarness::connected(config, 91, 1);
    let tracked_stream_id = engine
        .open_stream(now, b"open".to_vec(), None, StreamConfig::default())
        .unwrap();
    let write = engine.take_next_write().unwrap();
    let (_, initial_body) = decode_stream_body(&write.bytes, &session_key);
    assert!(matches!(
        &initial_body,
        StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq(1),
            frame: StreamFrame::Open(_),
            ..
        })
    ));
    let _outputs_written = engine.complete_write_collect(write.id, Ok(()));

    let stream = engine.streams.get(&tracked_stream_id).unwrap();
    assert_eq!(stream.control.in_flight.len(), 1);
    assert!(stream.control.in_flight.contains_key(&StreamSeq::START));
    assert_eq!(stream.control.next_tx_seq, StreamSeq(2));

    let _outputs_timeout =
        engine.run_tick_collect(now + config.stream_ack_timeout, EngineInput::TimerExpired);
    let retransmit_write = engine.take_next_write().unwrap();
    let (_, retransmit_body) = decode_stream_body(&retransmit_write.bytes, &session_key);
    assert!(matches!(
        retransmit_body,
        StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq(1),
            frame: StreamFrame::Open(StreamFrameOpen { stream_id, .. }),
            ..
        }) if stream_id == tracked_stream_id
    ));

    let stream = engine.streams.get(&tracked_stream_id).unwrap();
    assert_eq!(stream.control.in_flight.len(), 1);
    assert!(stream.control.in_flight.contains_key(&StreamSeq::START));
    assert_eq!(stream.control.next_tx_seq, StreamSeq(2));
    assert_eq!(
        stream
            .control
            .in_flight
            .get(&StreamSeq::START)
            .unwrap()
            .attempt,
        1
    );
}

#[test]
fn take_next_write_drains_multiple_stream_frames_before_completion() {
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(EngineConfig::default(), 93, 12);
    let stream_id = engine.state.next_stream_id(StreamNamespace::for_local(
        engine.engine.identity.xid,
        peer.xid,
    ));
    insert_unwritten_inflight_stream_with_data(&mut engine, stream_id, now, &[2, 3]);

    let writes = {
        let mut writes = Vec::new();
        while let Some(write) = engine.take_next_write() {
            writes.push(write);
        }
        writes
    };
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
    assert_eq!(engine.state.active_writes.len(), writes.len());
    assert!(engine.take_next_write().is_none());

    let stream = engine.streams.get(&stream_id).unwrap();
    assert!(
        stream
            .control
            .in_flight
            .iter()
            .all(|(_, in_flight)| matches!(in_flight.write_state, InFlightWriteState::Issued))
    );
}

#[test]
fn take_next_write_does_not_reissue_outstanding_frame() {
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key: _session_key,
    } = SingleEngineHarness::connected(EngineConfig::default(), 95, 13);
    let stream_id = engine.state.next_stream_id(StreamNamespace::for_local(
        engine.engine.identity.xid,
        peer.xid,
    ));
    insert_unwritten_inflight_stream_with_data(&mut engine, stream_id, now, &[]);

    let write = engine.take_next_write().unwrap();
    assert!(engine.take_next_write().is_none());
    assert!(engine.state.active_writes.contains_key(&write.id));
}

#[test]
fn take_next_write_round_robins_across_ready_streams() {
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(EngineConfig::default(), 97, 14);
    let stream_id1 = engine.state.next_stream_id(StreamNamespace::for_local(
        engine.engine.identity.xid,
        peer.xid,
    ));
    let stream_id2 = engine.state.next_stream_id(StreamNamespace::for_local(
        engine.engine.identity.xid,
        peer.xid,
    ));
    insert_unwritten_inflight_stream_with_data(&mut engine, stream_id1, now, &[2]);
    insert_unwritten_inflight_stream_with_data(&mut engine, stream_id2, now, &[2]);

    let scheduled: Vec<_> = {
        let mut writes = Vec::new();
        while let Some(write) = engine.take_next_write() {
            writes.push(write);
        }
        writes
    }
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
    let mut harness = Harness::connected(EngineConfig::default());
    let stream_id = harness
        .a
        .open_stream(
            harness.now,
            b"open-head".to_vec(),
            None,
            StreamConfig::default(),
        )
        .unwrap();
    let open_write = harness.a.take_next_write().unwrap();
    harness.complete_side_write(Side::A, open_write.id, Ok(()));
    harness.run_side(Side::B, EngineInput::Incoming(open_write.bytes));
    let _ = harness.a.drain_outputs();
    let _ = harness.b.drain_outputs();

    harness.run_side(
        Side::B,
        EngineInput::OutboundData {
            stream_id,
            bytes: b"resp".to_vec(),
        },
    );
    let _ = harness.a.drain_outputs();
    let _ = harness.b.drain_outputs();

    harness.now += EngineConfig::default().stream_ack_delay;
    harness.run_side(Side::B, EngineInput::TimerExpired);
    let _outputs_b_timer = harness.b.drain_outputs();

    assert!(harness.b.take_next_write().is_none());
}

#[test]
fn provisional_timeout_after_late_open_is_ignored() {
    let config = EngineConfig::default();
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(config, 63, 11);
    let stream_id =
        StreamId(StreamNamespace::for_local(peer.xid, engine.engine.identity.xid).bit() | 1);

    let early_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
        },
        &session_key,
        &StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq(2),
            ack: StreamAck::EMPTY,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Data(StreamFrameData {
                stream_id,
                chunk: BodyChunk {
                    bytes: b"hello".to_vec(),
                    fin: false,
                },
            }),
        }),
        [31; wire::encrypted_message::NONCE_SIZE],
    );
    let _ = engine.run_tick_collect(
        now,
        EngineInput::Incoming(wire::encode_record(&early_record)),
    );

    let open_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
        },
        &session_key,
        &StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq::START,
            ack: StreamAck::EMPTY,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Open(StreamFrameOpen {
                stream_id,
                request_head: b"late-open".to_vec(),
                request_prefix: None,
            }),
        }),
        [32; wire::encrypted_message::NONCE_SIZE],
    );
    let outputs_open = engine.run_tick_collect(
        now,
        EngineInput::Incoming(wire::encode_record(&open_record)),
    );
    assert!(outputs_open.iter().any(|output| matches!(
        output,
        EngineOutput::InboundStreamOpened { stream_id: id, .. } if *id == stream_id
    )));

    let _outputs_timeout =
        engine.run_tick_collect(now + config.packet_expiration, EngineInput::TimerExpired);

    assert!(matches!(
        engine.streams.get(&stream_id).map(|stream| &stream.role),
        Some(StreamRole::Responder(_))
    ));
    if let Some(write) = engine.take_next_write() {
        let (_, body) = decode_stream_body(&write.bytes, &session_key);
        assert!(!matches!(
            body,
            StreamBody::Message(StreamMessage {
                frame: StreamFrame::Close(_),
                ..
            })
        ));
    }
}

#[test]
fn ack_only_write_failure_immediately_requeues_ack_without_spending_extra_seq() {
    let config = EngineConfig::default();
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(config, 65, 12);
    let stream_id =
        StreamId(StreamNamespace::for_local(peer.xid, engine.engine.identity.xid).bit() | 1);
    let open_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
        },
        &session_key,
        &StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq::START,
            ack: StreamAck::EMPTY,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Open(StreamFrameOpen {
                stream_id,
                request_head: b"open".to_vec(),
                request_prefix: None,
            }),
        }),
        [33; wire::encrypted_message::NONCE_SIZE],
    );
    let outputs_open = engine.run_tick_collect(
        now,
        EngineInput::Incoming(wire::encode_record(&open_record)),
    );
    assert!(outputs_open.iter().any(|output| matches!(
        output,
        EngineOutput::InboundStreamOpened { stream_id: id, .. } if *id == stream_id
    )));

    let _outputs_ack =
        engine.run_tick_collect(now + config.stream_ack_delay, EngineInput::TimerExpired);
    let ack_write = engine.take_next_write().unwrap();
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

    let outputs_failed = engine.complete_write_collect(ack_write.id, Err(QlError::SendFailed));
    assert!(
        !outputs_failed
            .iter()
            .any(|output| matches!(output, EngineOutput::StreamReaped { .. }))
    );
    let retry_write = engine.take_next_write().unwrap();
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

    let _ = engine.complete_write_collect(retry_write.id, Ok(()));

    let _outputs_data = engine.run_tick_collect(
        now + config.stream_ack_delay,
        EngineInput::OutboundData {
            stream_id,
            bytes: b"resp".to_vec(),
        },
    );
    let response_write = engine.take_next_write().unwrap();
    let (_, body) = decode_stream_body(&response_write.bytes, &session_key);
    assert!(matches!(
        body,
        StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq::START,
            frame: StreamFrame::Data(StreamFrameData {
                stream_id: id,
                chunk: BodyChunk { bytes, fin: false },
            }),
            ..
        }) if id == stream_id && bytes == b"resp"
    ));
    let stream = engine.streams.get(&stream_id).unwrap();
    assert_eq!(stream.control.next_tx_seq, StreamSeq(2));
}

#[test]
fn duplicate_committed_data_is_acked_without_redelivery() {
    let config = EngineConfig::default();
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(config, 67, 13);
    let stream_id =
        StreamId(StreamNamespace::for_local(peer.xid, engine.engine.identity.xid).bit() | 1);

    for (nonce, body) in [
        (
            34u8,
            StreamBody::Message(StreamMessage {
                tx_seq: StreamSeq::START,
                ack: StreamAck::EMPTY,
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
                ack: StreamAck::EMPTY,
                valid_until: wire::now_secs().saturating_add(60),
                frame: StreamFrame::Data(StreamFrameData {
                    stream_id,
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
                sender: peer.xid,
                recipient: engine.engine.identity.xid,
            },
            &session_key,
            &body,
            [nonce; wire::encrypted_message::NONCE_SIZE],
        );
        let _ = engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&record)));
    }

    let duplicate_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
        },
        &session_key,
        &StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq(2),
            ack: StreamAck::EMPTY,
            valid_until: wire::now_secs().saturating_add(60),
            frame: StreamFrame::Data(StreamFrameData {
                stream_id,
                chunk: BodyChunk {
                    bytes: b"hello".to_vec(),
                    fin: false,
                },
            }),
        }),
        [36; wire::encrypted_message::NONCE_SIZE],
    );
    let outputs_dup = engine.run_tick_collect(
        now,
        EngineInput::Incoming(wire::encode_record(&duplicate_record)),
    );

    assert!(
        !outputs_dup
            .iter()
            .any(|output| matches!(output, EngineOutput::InboundData { .. }))
    );
    let ack_write = engine.take_next_write().unwrap();
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
    let mut config = EngineConfig::default();
    config.stream_fast_retransmit_threshold = 2;
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(config, 69, 14);
    let stream_id = engine.state.next_stream_id(StreamNamespace::for_local(
        engine.engine.identity.xid,
        peer.xid,
    ));
    insert_inflight_gap_stream(&mut engine, stream_id, now);

    let local_xid = engine.engine.identity.xid;
    let remote_xid = peer.xid;
    let ack_record = |nonce: u8| {
        wire::stream::encrypt_stream(
            QlHeader {
                sender: remote_xid,
                recipient: local_xid,
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

    let _outputs_first = engine.run_tick_collect(
        now,
        EngineInput::Incoming(wire::encode_record(&ack_record(37))),
    );
    let write = engine.take_next_write().unwrap();
    let (_, body) = decode_stream_body(&write.bytes, &session_key);
    assert!(matches!(
        body,
        StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq(3),
            ..
        })
    ));

    let _ = engine.complete_write_collect(write.id, Ok(()));

    let _outputs_second = engine.run_tick_collect(
        now,
        EngineInput::Incoming(wire::encode_record(&ack_record(38))),
    );
    assert!(engine.take_next_write().is_none());
}

#[test]
fn fast_recovery_clears_after_gap_is_acked_and_allows_next_gap() {
    let mut config = EngineConfig::default();
    config.stream_fast_retransmit_threshold = 1;
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(config, 73, 15);
    let stream_id = engine.state.next_stream_id(StreamNamespace::for_local(
        engine.engine.identity.xid,
        peer.xid,
    ));
    insert_inflight_stream_with_data(&mut engine, stream_id, now, &[2, 3, 4, 5, 6]);

    let first_ack = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
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
    let _outputs_first =
        engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&first_ack)));
    let write_first = engine.take_next_write().unwrap();
    let (_, first_body) = decode_stream_body(&write_first.bytes, &session_key);
    assert!(matches!(
        first_body,
        StreamBody::Message(StreamMessage {
            tx_seq: StreamSeq(3),
            ..
        })
    ));

    let _ = engine.complete_write_collect(write_first.id, Ok(()));

    let second_ack = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
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
    let _outputs_second =
        engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&second_ack)));
    let write_second = engine.take_next_write().unwrap();
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
    let mut config = EngineConfig::default();
    config.stream_fast_retransmit_threshold = 2;
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(config, 75, 16);
    let stream_id = engine.state.next_stream_id(StreamNamespace::for_local(
        engine.engine.identity.xid,
        peer.xid,
    ));
    insert_inflight_gap_stream(&mut engine, stream_id, now);
    engine
        .streams
        .get_mut(&stream_id)
        .unwrap()
        .control
        .set_retry_deadline(StreamSeq(3), now);

    let ack_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
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
    let _outputs_ack =
        engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&ack_record)));
    let _write = engine.take_next_write().unwrap();
    assert!(engine.take_next_write().is_none());

    let _outputs_timeout = engine.run_tick_collect(now, EngineInput::TimerExpired);
    assert!(engine.take_next_write().is_none());
}

#[test]
fn replayed_heartbeat_is_ignored() {
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(EngineConfig::default(), 101, 4);
    let heartbeat = wire::heartbeat::encrypt_heartbeat(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
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

    let _first = engine.run_tick_collect(now, EngineInput::Incoming(bytes.clone()));
    let first_write = engine.take_next_write().unwrap();
    let first_record = wire::decode_record(&first_write.bytes).unwrap();
    assert!(matches!(first_record.payload, QlPayload::Heartbeat(_)));
    let _ = engine.complete_write_collect(first_write.id, Ok(()));

    let _second = engine.run_tick_collect(now, EngineInput::Incoming(bytes));
    assert!(engine.take_next_write().is_none());
}

#[test]
fn handshake_deadline_is_derived_from_peer_state() {
    let mut config = EngineConfig::default();
    config.handshake_timeout = Duration::from_secs(5);

    let identity = test_identity();
    let peer_identity = test_identity();
    let mut engine = EngineWrapper::new(
        Engine::new(
            config,
            identity.clone(),
            Some(peer_from_identity(&peer_identity)),
        ),
        TestCrypto::new(103),
    );
    let now = Instant::now();

    let _outputs = engine.run_tick_collect(now, EngineInput::Connect);
    assert_eq!(engine.next_deadline(), Some(now + Duration::from_secs(5)));

    let write = engine.take_next_write().unwrap();
    let _outputs = engine.complete_write_collect(write.id, Ok(()));
    assert_eq!(engine.next_deadline(), Some(now + Duration::from_secs(5)));

    let outputs = engine.run_tick_collect(now + Duration::from_secs(4), EngineInput::TimerExpired);
    assert!(!outputs.iter().any(|output| {
        matches!(
            output,
            EngineOutput::PeerStatusChanged {
                session: PeerSession::Disconnected,
                ..
            }
        )
    }));
    assert_eq!(engine.next_deadline(), Some(now + Duration::from_secs(5)));

    let outputs = engine.run_tick_collect(now + Duration::from_secs(5), EngineInput::TimerExpired);
    assert!(outputs.iter().any(|output| {
        matches!(
            output,
            EngineOutput::PeerStatusChanged {
                session: PeerSession::Disconnected,
                ..
            }
        )
    }));
}

#[test]
fn initiator_waits_for_ready_before_connecting() {
    let config = EngineConfig::default();
    let identity = test_identity();
    let peer_identity = test_identity();
    let responder_crypto = TestCrypto::new(104);
    let mut engine = EngineWrapper::new(
        Engine::new(
            config,
            identity.clone(),
            Some(peer_from_identity(&peer_identity)),
        ),
        TestCrypto::new(103),
    );
    let now = Instant::now();

    let _outputs = engine.run_tick_collect(now, EngineInput::Connect);

    let hello_write = engine.take_next_write().unwrap();
    let hello_record = wire::decode_record(&hello_write.bytes).unwrap();
    let QlPayload::Handshake(wire::handshake::HandshakeRecord::Hello(hello)) = hello_record.payload
    else {
        panic!("expected hello record");
    };
    let _outputs = engine.complete_write_collect(hello_write.id, Ok(()));

    let hello_bytes = wire::encode_value(&hello);
    let hello_view = wire::access_value::<wire::handshake::ArchivedHello>(&hello_bytes).unwrap();
    let (reply, _secrets) = wire::handshake::respond_hello(
        &peer_identity,
        &responder_crypto,
        identity.xid,
        &identity.signing_public_key,
        &identity.encapsulation_public_key,
        hello_view,
        wire::ControlMeta {
            packet_id: PacketId(77),
            valid_until: wire::now_secs().saturating_add(60),
        },
    )
    .unwrap();
    let reply_record = QlRecord {
        header: QlHeader {
            sender: peer_identity.xid,
            recipient: identity.xid,
        },
        payload: QlPayload::Handshake(wire::handshake::HandshakeRecord::HelloReply(reply)),
    };
    let _outputs = engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&reply_record)));

    let confirm_write = engine.take_next_write().unwrap();
    let _outputs = engine.complete_write_collect(confirm_write.id, Ok(()));

    assert!(matches!(
        engine.peer.as_ref().map(|peer| &peer.session),
        Some(PeerSession::Initiator {
            stage: InitiatorStage::WaitingReady,
            ..
        })
    ));
    assert!(matches!(
        engine.open_stream(now, Vec::new(), None, StreamConfig::default()),
        Err(QlError::MissingSession)
    ));

    let pending_session_key = match engine.peer.as_ref().map(|peer| &peer.session) {
        Some(PeerSession::Initiator { session_key, .. }) => session_key.clone(),
        other => panic!("expected pending initiator session, got {other:?}"),
    };
    let ready_record = QlRecord {
        header: QlHeader {
            sender: peer_identity.xid,
            recipient: identity.xid,
        },
        payload: QlPayload::Handshake(wire::handshake::HandshakeRecord::Ready(
            wire::handshake::build_ready(
                QlHeader {
                    sender: peer_identity.xid,
                    recipient: identity.xid,
                },
                &pending_session_key,
                wire::ControlMeta {
                    packet_id: PacketId(78),
                    valid_until: wire::now_secs().saturating_add(60),
                },
                [9; wire::encrypted_message::NONCE_SIZE],
            ),
        )),
    };
    let outputs = engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&ready_record)));

    assert!(matches!(
        engine.peer.as_ref().map(|peer| &peer.session),
        Some(PeerSession::Connected { .. })
    ));
    assert!(outputs.iter().any(|output| matches!(
        output,
        EngineOutput::PeerStatusChanged {
            session: PeerSession::Connected { .. },
            ..
        }
    )));
}

#[test]
fn keepalive_deadline_is_derived_from_peer_state() {
    let mut config = EngineConfig::default();
    config.keep_alive = Some(KeepAliveConfig {
        interval: Duration::from_secs(5),
        timeout: Duration::from_secs(7),
    });
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(config, 103, 6);

    let heartbeat = encrypt_heartbeat_record(
        peer.xid,
        engine.engine.identity.xid,
        &session_key,
        1,
        [7; wire::encrypted_message::NONCE_SIZE],
    );
    let outputs =
        engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&heartbeat)));
    let _ = outputs;
    assert_eq!(engine.next_deadline(), Some(now + Duration::from_secs(5)));

    let write = engine.take_next_write().unwrap();
    let record = wire::decode_record(&write.bytes).unwrap();
    assert!(matches!(record.payload, QlPayload::Heartbeat(_)));
    let _ = engine.complete_write_collect(write.id, Ok(()));

    let outputs = engine.run_tick_collect(now + Duration::from_secs(5), EngineInput::TimerExpired);
    let _ = outputs;
    assert_eq!(engine.next_deadline(), Some(now + Duration::from_secs(12)));

    let write = engine.take_next_write().unwrap();
    let record = wire::decode_record(&write.bytes).unwrap();
    assert!(matches!(record.payload, QlPayload::Heartbeat(_)));
    let _ = engine.complete_write_collect(write.id, Ok(()));

    let outputs = engine.run_tick_collect(now + Duration::from_secs(12), EngineInput::TimerExpired);
    assert!(outputs.iter().any(|output| {
        matches!(
            output,
            EngineOutput::PeerStatusChanged {
                session: PeerSession::Disconnected,
                ..
            }
        )
    }));
}

#[test]
fn replayed_unpair_is_ignored_after_rebind() {
    let config = EngineConfig::default();
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key: _session_key,
    } = SingleEngineHarness::connected(config, 111, 5);
    let peer_b = peer_from_identity(&peer);
    let bytes = wire::encode_record(&wire::unpair::build_unpair_record(
        &peer,
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
        },
        wire::ControlMeta {
            packet_id: PacketId(9),
            valid_until: wire::now_secs().saturating_add(60),
        },
    ));

    let first = engine.run_tick_collect(now, EngineInput::Incoming(bytes.clone()));
    assert!(
        first
            .iter()
            .any(|output| matches!(output, EngineOutput::ClearPeer))
    );
    assert!(engine.peer.is_none());

    let _ = engine.run_tick_collect(now, EngineInput::BindPeer(peer_b.clone()));
    assert!(engine.peer.is_some());

    let second = engine.run_tick_collect(now, EngineInput::Incoming(bytes));
    assert!(
        !second
            .iter()
            .any(|output| matches!(output, EngineOutput::ClearPeer))
    );
    assert_eq!(
        engine.peer.as_ref().map(|peer| peer.peer),
        Some(peer_b.peer)
    );
}
