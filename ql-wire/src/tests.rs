use std::ops::RangeInclusive;

use super::*;

fn decode_handshake_record(bytes: &[u8]) -> QlHandshakeRecord {
    decode_record(bytes).unwrap().1
}

fn decode_session_record(bytes: &[u8]) -> QlSessionRecord<Vec<u8>> {
    let (_, record) = decode_record::<QlSessionRecord<_>, _>(bytes).unwrap();
    record.into_owned()
}

fn xid(byte: u8) -> XID {
    XID([byte; XID::SIZE])
}

fn varint(value: u64) -> VarInt {
    VarInt::from_u64(value).unwrap()
}

fn record_seq(value: u64) -> RecordSeq {
    RecordSeq(varint(value))
}

fn record_ack_range(start: u64, end: u64) -> RangeInclusive<RecordSeq> {
    record_seq(start)..=record_seq(end)
}

fn stream_id(value: u64) -> StreamId {
    StreamId(varint(value))
}

fn handshake_meta(id: u32) -> HandshakeMeta {
    HandshakeMeta {
        handshake_id: HandshakeId(id),
        valid_until: 10_000 + u64::from(id),
    }
}

fn handshake_transport_params(window: u32) -> TransportParams {
    TransportParams {
        initial_stream_receive_window: window,
    }
}

fn handshake_header(sender: u8, recipient: u8) -> HandshakeHeader {
    HandshakeHeader {
        sender: xid(sender),
        recipient: xid(recipient),
    }
}

fn pairing_token(byte: u8) -> PairingToken {
    PairingToken([byte; PairingToken::SIZE])
}

fn xx_header(byte: u8) -> XxHeader {
    XxHeader {
        pairing_token: pairing_token(byte),
    }
}

fn encrypt_record(
    crypto: &impl QlCrypto,
    header: SessionHeader,
    session_key: &SessionKey,
    body: &[SessionFrame<Vec<u8>>],
) -> QlSessionRecord<Vec<u8>> {
    let mut builder = SessionRecordBuilder::new(header.seq, usize::MAX);
    for frame in body {
        let pushed = builder.push_frame(frame);
        debug_assert!(pushed);
    }
    decode_session_record(
        builder
            .encrypt(crypto, header.connection_id, session_key)
            .as_slice(),
    )
}

#[test]
fn peer_bundle_round_trip() {
    let crypto = SoftwareCrypto;
    let identity = test_identity(&crypto).with_capabilities(0x55aa_33cc);
    let bundle = identity.bundle();

    let encoded = bundle.encode_vec();
    let decoded = PeerBundle::decode_exact(encoded.as_slice()).unwrap();

    assert_eq!(decoded, bundle);
}

#[test]
fn handshake_record_round_trip_supports_ik_kk_and_xx() {
    let ik = QlHandshakeRecord::Ik1(Ik1 {
        header: handshake_header(1, 2),
        meta: handshake_meta(1),
        transport_params: handshake_transport_params(65_536),
        skem_ciphertext: MlKemCiphertext::new(Box::new([7; MlKemCiphertext::SIZE])),
        ephemeral: EphemeralPublicKey {
            mlkem_public_key: MlKemPublicKey::new(Box::new([9; MlKemPublicKey::SIZE])),
        },
        static_bundle: EncryptedPeerBundle::new(Box::new([13; EncryptedPeerBundle::WIRE_SIZE])),
    });
    let ik_encoded = encode_record_vec(RecordType::Handshake, &ik);
    assert_eq!(
        RecordHeader::decode_bytes(ik_encoded.as_slice()).unwrap(),
        RecordHeader {
            version: QL_WIRE_VERSION,
            record_type: RecordType::Handshake,
        }
    );
    assert_eq!(decode_handshake_record(ik_encoded.as_slice()), ik);

    let kk = QlHandshakeRecord::Kk1(Kk1 {
        header: handshake_header(1, 2),
        meta: handshake_meta(2),
        transport_params: handshake_transport_params(131_072),
        skem_ciphertext: MlKemCiphertext::new(Box::new([11; MlKemCiphertext::SIZE])),
        ephemeral: EphemeralPublicKey {
            mlkem_public_key: MlKemPublicKey::new(Box::new([15; MlKemPublicKey::SIZE])),
        },
    });
    let kk_encoded = encode_record_vec(RecordType::Handshake, &kk);
    assert_eq!(
        RecordHeader::decode_bytes(kk_encoded.as_slice()).unwrap(),
        RecordHeader {
            version: QL_WIRE_VERSION,
            record_type: RecordType::Handshake,
        }
    );
    assert_eq!(decode_handshake_record(kk_encoded.as_slice()), kk);

    let xx = QlHandshakeRecord::Xx1(Xx1 {
        header: xx_header(3),
        meta: handshake_meta(3),
        transport_params: handshake_transport_params(196_608),
        ephemeral: EphemeralPublicKey {
            mlkem_public_key: MlKemPublicKey::new(Box::new([17; MlKemPublicKey::SIZE])),
        },
    });
    let xx_encoded = encode_record_vec(RecordType::Handshake, &xx);
    assert_eq!(
        RecordHeader::decode_bytes(xx_encoded.as_slice()).unwrap(),
        RecordHeader {
            version: QL_WIRE_VERSION,
            record_type: RecordType::Handshake,
        }
    );
    assert_eq!(decode_handshake_record(xx_encoded.as_slice()), xx);
}

#[test]
fn ik_handshake_rejects_tampered_handshake_meta() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);

    let mut initiator_state = IkHandshake::new_initiator(
        &crypto,
        initiator,
        responder.bundle(),
        TransportParams::default(),
    );
    let mut responder_state =
        IkHandshake::new_responder(&crypto, responder, None, TransportParams::default());

    let m1 = initiator_state
        .write_1(&crypto, handshake_meta(77))
        .unwrap();
    responder_state.read_1(&crypto, 0, &m1).unwrap();

    let mut m2 = responder_state
        .write_2(&crypto, handshake_meta(77))
        .unwrap();
    m2.meta.handshake_id = HandshakeId(78);

    assert_eq!(
        initiator_state.read_2(&crypto, 0, &m2),
        Err(WireError::InvalidPayload)
    );
}

#[test]
fn kk_handshake_rejects_tampered_handshake_header() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);

    let mut initiator_state = KkHandshake::new_initiator(
        &crypto,
        initiator.clone(),
        responder.bundle(),
        TransportParams::default(),
    );
    let mut responder_state = KkHandshake::new_responder(
        &crypto,
        responder,
        initiator.bundle(),
        TransportParams::default(),
    );

    let m1 = initiator_state
        .write_1(&crypto, handshake_meta(88))
        .unwrap();
    responder_state.read_1(&crypto, 0, &m1).unwrap();

    let mut m2 = responder_state
        .write_2(&crypto, handshake_meta(88))
        .unwrap();
    m2.header = handshake_header(9, 1);

    assert_eq!(
        initiator_state.read_2(&crypto, 0, &m2),
        Err(WireError::InvalidPayload)
    );
}

#[test]
fn ik_handshake_rejects_tampered_transport_params() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);

    let mut initiator_state = IkHandshake::new_initiator(
        &crypto,
        initiator,
        responder.bundle(),
        handshake_transport_params(4096),
    );
    let mut responder_state =
        IkHandshake::new_responder(&crypto, responder, None, handshake_transport_params(8192));

    let m1 = initiator_state
        .write_1(&crypto, handshake_meta(89))
        .unwrap();
    responder_state.read_1(&crypto, 0, &m1).unwrap();

    let mut m2 = responder_state
        .write_2(&crypto, handshake_meta(89))
        .unwrap();
    m2.transport_params.initial_stream_receive_window += 1;

    assert_eq!(
        initiator_state.read_2(&crypto, 0, &m2),
        Err(WireError::DecryptFailed)
    );
}

#[test]
fn ik_handshake_rejects_tampered_handshake_header() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);

    let mut initiator_state = IkHandshake::new_initiator(
        &crypto,
        initiator,
        responder.bundle(),
        TransportParams::default(),
    );
    let mut responder_state =
        IkHandshake::new_responder(&crypto, responder, None, TransportParams::default());

    let mut m1 = initiator_state
        .write_1(&crypto, handshake_meta(90))
        .unwrap();
    m1.header.sender = xid(9);

    assert_eq!(
        responder_state.read_1(&crypto, 0, &m1),
        Err(WireError::DecryptFailed)
    );
}

#[test]
fn ik_handshake_rejects_bound_remote_bundle_mismatch() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let bogus = test_identity(&crypto);

    let mut initiator_state = IkHandshake::new_initiator(
        &crypto,
        initiator,
        responder.bundle(),
        TransportParams::default(),
    );
    let mut responder_state = IkHandshake::new_responder(
        &crypto,
        responder,
        Some(bogus.bundle()),
        TransportParams::default(),
    );

    let m1 = initiator_state
        .write_1(&crypto, handshake_meta(91))
        .unwrap();

    assert_eq!(
        responder_state.read_1(&crypto, 0, &m1),
        Err(WireError::InvalidPayload)
    );
}

#[test]
fn ik_handshake_rejects_expired_message() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);

    let mut initiator_state = IkHandshake::new_initiator(
        &crypto,
        initiator,
        responder.bundle(),
        TransportParams::default(),
    );
    let mut responder_state =
        IkHandshake::new_responder(&crypto, responder, None, TransportParams::default());

    let m1 = initiator_state
        .write_1(
            &crypto,
            HandshakeMeta {
                handshake_id: HandshakeId(92),
                valid_until: 5,
            },
        )
        .unwrap();

    assert_eq!(
        responder_state.read_1(&crypto, 6, &m1),
        Err(WireError::Expired)
    );
}

#[test]
fn ik_handshake_round_trip_derives_matching_transport_and_learns_remote() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);

    let initiator_params = handshake_transport_params(4096);
    let responder_params = handshake_transport_params(8192);
    let mut initiator_state = IkHandshake::new_initiator(
        &crypto,
        initiator.clone(),
        responder.bundle(),
        initiator_params,
    );
    let mut responder_state =
        IkHandshake::new_responder(&crypto, responder.clone(), None, responder_params);

    let m1 = initiator_state
        .write_1(&crypto, handshake_meta(11))
        .unwrap();
    responder_state.read_1(&crypto, 0, &m1).unwrap();

    let m2 = responder_state
        .write_2(&crypto, handshake_meta(11))
        .unwrap();
    initiator_state.read_2(&crypto, 0, &m2).unwrap();

    let initiator_final = initiator_state.finalize(&crypto).unwrap();
    let responder_final = responder_state.finalize(&crypto).unwrap();

    assert_eq!(
        initiator_final.handshake_hash,
        responder_final.handshake_hash
    );
    assert_eq!(initiator_final.tx_key, responder_final.rx_key);
    assert_eq!(initiator_final.rx_key, responder_final.tx_key);
    assert_eq!(
        initiator_final.tx_connection_id,
        responder_final.rx_connection_id
    );
    assert_eq!(
        initiator_final.rx_connection_id,
        responder_final.tx_connection_id
    );
    assert_eq!(initiator_final.remote_bundle, responder.bundle());
    assert_eq!(responder_final.remote_bundle, initiator.bundle());
    assert_eq!(initiator_final.remote_transport_params, responder_params);
    assert_eq!(responder_final.remote_transport_params, initiator_params);
}

#[test]
fn ik_handshake_round_trip_derives_matching_transport_with_bound_responder() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);

    let initiator_params = handshake_transport_params(16_384);
    let responder_params = handshake_transport_params(32_768);
    let mut initiator_state = IkHandshake::new_initiator(
        &crypto,
        initiator.clone(),
        responder.bundle(),
        initiator_params,
    );
    let mut responder_state = IkHandshake::new_responder(
        &crypto,
        responder.clone(),
        Some(initiator.bundle()),
        responder_params,
    );

    let m1 = initiator_state
        .write_1(&crypto, handshake_meta(12))
        .unwrap();
    responder_state.read_1(&crypto, 0, &m1).unwrap();

    let m2 = responder_state
        .write_2(&crypto, handshake_meta(12))
        .unwrap();
    initiator_state.read_2(&crypto, 0, &m2).unwrap();

    let initiator_final = initiator_state.finalize(&crypto).unwrap();
    let responder_final = responder_state.finalize(&crypto).unwrap();

    assert_eq!(
        initiator_final.handshake_hash,
        responder_final.handshake_hash
    );
    assert_eq!(initiator_final.tx_key, responder_final.rx_key);
    assert_eq!(initiator_final.rx_key, responder_final.tx_key);
    assert_eq!(
        initiator_final.tx_connection_id,
        responder_final.rx_connection_id
    );
    assert_eq!(
        initiator_final.rx_connection_id,
        responder_final.tx_connection_id
    );
    assert_eq!(initiator_final.remote_bundle, responder.bundle());
    assert_eq!(responder_final.remote_bundle, initiator.bundle());
    assert_eq!(initiator_final.remote_transport_params, responder_params);
    assert_eq!(responder_final.remote_transport_params, initiator_params);
}

#[test]
fn kk_handshake_round_trip_derives_matching_transport() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);

    let initiator_params = handshake_transport_params(24_576);
    let responder_params = handshake_transport_params(49_152);
    let mut initiator_state = KkHandshake::new_initiator(
        &crypto,
        initiator.clone(),
        responder.bundle(),
        initiator_params,
    );
    let mut responder_state = KkHandshake::new_responder(
        &crypto,
        responder.clone(),
        initiator.bundle(),
        responder_params,
    );

    let m1 = initiator_state
        .write_1(&crypto, handshake_meta(21))
        .unwrap();
    responder_state.read_1(&crypto, 0, &m1).unwrap();

    let m2 = responder_state
        .write_2(&crypto, handshake_meta(21))
        .unwrap();
    initiator_state.read_2(&crypto, 0, &m2).unwrap();

    let initiator_final = initiator_state.finalize(&crypto).unwrap();
    let responder_final = responder_state.finalize(&crypto).unwrap();

    assert_eq!(
        initiator_final.handshake_hash,
        responder_final.handshake_hash
    );
    assert_eq!(initiator_final.tx_key, responder_final.rx_key);
    assert_eq!(initiator_final.rx_key, responder_final.tx_key);
    assert_eq!(
        initiator_final.tx_connection_id,
        responder_final.rx_connection_id
    );
    assert_eq!(
        initiator_final.rx_connection_id,
        responder_final.tx_connection_id
    );
    assert_eq!(initiator_final.remote_bundle, responder.bundle());
    assert_eq!(responder_final.remote_bundle, initiator.bundle());
    assert_eq!(initiator_final.remote_transport_params, responder_params);
    assert_eq!(responder_final.remote_transport_params, initiator_params);
}

#[test]
fn kk_handshake_rejects_tampered_transport_params() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);

    let mut initiator_state = KkHandshake::new_initiator(
        &crypto,
        initiator.clone(),
        responder.bundle(),
        handshake_transport_params(12288),
    );
    let mut responder_state = KkHandshake::new_responder(
        &crypto,
        responder,
        initiator.bundle(),
        handshake_transport_params(24576),
    );

    let m1 = initiator_state
        .write_1(&crypto, handshake_meta(22))
        .unwrap();
    responder_state.read_1(&crypto, 0, &m1).unwrap();

    let mut m2 = responder_state
        .write_2(&crypto, handshake_meta(22))
        .unwrap();
    m2.transport_params.initial_stream_receive_window += 1;

    assert_eq!(
        initiator_state.read_2(&crypto, 0, &m2),
        Err(WireError::DecryptFailed)
    );
}

#[test]
fn xx_handshake_rejects_tampered_pairing_token() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let token = pairing_token(7);

    let mut initiator_state =
        XxHandshake::new_initiator(&crypto, initiator, token, TransportParams::default());
    let mut responder_state =
        XxHandshake::new_responder(&crypto, responder, token, TransportParams::default());

    let mut m1 = initiator_state
        .write_1(&crypto, handshake_meta(31))
        .unwrap();
    m1.header = xx_header(8);

    assert_eq!(
        responder_state.read_1(&crypto, 0, &m1),
        Err(WireError::InvalidPayload)
    );
}

#[test]
fn xx_handshake_rejects_repeated_transport_param_change() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let token = pairing_token(9);

    let mut initiator_state = XxHandshake::new_initiator(
        &crypto,
        initiator.clone(),
        token,
        handshake_transport_params(12_288),
    );
    let mut responder_state = XxHandshake::new_responder(
        &crypto,
        responder,
        token,
        handshake_transport_params(24_576),
    );

    let m1 = initiator_state
        .write_1(&crypto, handshake_meta(32))
        .unwrap();
    responder_state.read_1(&crypto, 0, &m1).unwrap();

    let m2 = responder_state
        .write_2(&crypto, handshake_meta(32))
        .unwrap();
    initiator_state.read_2(&crypto, 0, &m2).unwrap();

    let mut m3 = initiator_state
        .write_3(&crypto, handshake_meta(32))
        .unwrap();
    m3.transport_params.initial_stream_receive_window += 1;

    assert_eq!(
        responder_state.read_3(&crypto, 0, &m3),
        Err(WireError::InvalidPayload)
    );
}

#[test]
fn xx_handshake_round_trip_derives_matching_transport_and_learns_remote() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let token = pairing_token(10);

    let initiator_params = handshake_transport_params(28_672);
    let responder_params = handshake_transport_params(57_344);
    let mut initiator_state =
        XxHandshake::new_initiator(&crypto, initiator.clone(), token, initiator_params);
    let mut responder_state =
        XxHandshake::new_responder(&crypto, responder.clone(), token, responder_params);

    assert_eq!(initiator_state.pairing_token(), token);
    assert_eq!(responder_state.pairing_token(), token);
    assert!(initiator_state.remote_bundle().is_none());
    assert!(responder_state.remote_bundle().is_none());

    let m1 = initiator_state
        .write_1(&crypto, handshake_meta(33))
        .unwrap();
    responder_state.read_1(&crypto, 0, &m1).unwrap();

    let m2 = responder_state
        .write_2(&crypto, handshake_meta(33))
        .unwrap();
    initiator_state.read_2(&crypto, 0, &m2).unwrap();
    assert_eq!(initiator_state.remote_bundle(), Some(&responder.bundle()));
    assert!(responder_state.remote_bundle().is_none());

    let m3 = initiator_state
        .write_3(&crypto, handshake_meta(33))
        .unwrap();
    responder_state.read_3(&crypto, 0, &m3).unwrap();
    assert_eq!(responder_state.remote_bundle(), Some(&initiator.bundle()));

    let m4 = responder_state
        .write_4(&crypto, handshake_meta(33))
        .unwrap();
    initiator_state.read_4(&crypto, 0, &m4).unwrap();

    let initiator_final = initiator_state.finalize(&crypto).unwrap();
    let responder_final = responder_state.finalize(&crypto).unwrap();

    assert_eq!(
        initiator_final.handshake_hash,
        responder_final.handshake_hash
    );
    assert_eq!(initiator_final.tx_key, responder_final.rx_key);
    assert_eq!(initiator_final.rx_key, responder_final.tx_key);
    assert_eq!(
        initiator_final.tx_connection_id,
        responder_final.rx_connection_id
    );
    assert_eq!(
        initiator_final.rx_connection_id,
        responder_final.tx_connection_id
    );
    assert_eq!(initiator_final.remote_bundle, responder.bundle());
    assert_eq!(responder_final.remote_bundle, initiator.bundle());
    assert_eq!(initiator_final.remote_transport_params, responder_params);
    assert_eq!(responder_final.remote_transport_params, initiator_params);
}

#[test]
fn encrypted_session_record_round_trip_uses_connection_id_header() {
    let crypto = SoftwareCrypto;
    let header = SessionHeader {
        connection_id: ConnectionId::from_data([0x44; ConnectionId::SIZE]),
        seq: record_seq(11),
    };
    let body = vec![
        SessionFrame::Ping,
        SessionFrame::Ack(
            RecordAck::from_ranges([record_ack_range(20, 23), record_ack_range(12, 13)]).unwrap(),
        ),
        SessionFrame::StreamWindow(StreamWindow {
            stream_id: stream_id(9),
            maximum_offset: varint(65_536),
        }),
        SessionFrame::StreamData(StreamData {
            stream_id: stream_id(9),
            offset: varint(1024),
            header: None,
            bytes: b"hello".to_vec(),
            fin: true,
        }),
        SessionFrame::StreamClose(StreamClose {
            stream_id: stream_id(9),
            target: CloseTarget::Both,
            code: StreamCloseCode::CANCELLED,
        }),
        SessionFrame::Close(SessionClose {
            code: SessionCloseCode::TIMEOUT,
        }),
    ];
    let session_key = SessionKey::from_data([7; SessionKey::SIZE]);
    let record = encrypt_record(&crypto, header, &session_key, &body);

    let bytes = encode_record_vec(RecordType::Session, &record);
    assert_eq!(
        RecordHeader::decode_bytes(bytes.as_slice()).unwrap(),
        RecordHeader {
            version: QL_WIRE_VERSION,
            record_type: RecordType::Session,
        }
    );
    let decoded = decode_session_record(bytes.as_slice());
    assert_eq!(decoded.header, header);
    let encrypted = decoded.payload;

    let decrypted =
        encrypted::decrypt_record(&crypto, &header, encrypted.clone(), &session_key).unwrap();
    assert_eq!(decode_session_frames(&decrypted).unwrap(), body);

    let wrong_header = SessionHeader {
        connection_id: ConnectionId::from_data([0x99; ConnectionId::SIZE]),
        seq: header.seq,
    };
    assert_eq!(
        encrypted::decrypt_record(&crypto, &wrong_header, encrypted.clone(), &session_key),
        Err(WireError::DecryptFailed)
    );

    let wrong_seq_header = SessionHeader {
        connection_id: header.connection_id,
        seq: record_seq(header.seq.into_inner() + 1),
    };
    assert_eq!(
        encrypted::decrypt_record(&crypto, &wrong_seq_header, encrypted, &session_key),
        Err(WireError::DecryptFailed)
    );
}

#[test]
fn session_varint_fields_expand_at_expected_boundaries() {
    let short_header = SessionHeader {
        connection_id: ConnectionId::from_data([0x11; ConnectionId::SIZE]),
        seq: record_seq(63),
    };
    let long_header = SessionHeader {
        connection_id: ConnectionId::from_data([0x11; ConnectionId::SIZE]),
        seq: record_seq(64),
    };

    assert_eq!(short_header.encode_vec().len(), ConnectionId::SIZE + 1);
    assert_eq!(long_header.encode_vec().len(), ConnectionId::SIZE + 2);

    let frame = StreamData {
        stream_id: stream_id(64),
        offset: varint(16_384),
        header: None,
        fin: true,
        bytes: b"abc".to_vec(),
    };
    let encoded = frame.encode_vec();

    assert_eq!(
        StreamData::decode_exact(encoded.as_slice())
            .unwrap()
            .into_owned(),
        frame
    );
}

#[test]
fn protocol_record_size_breakdown() {
    fn print_size(label: &str, size: usize) {
        println!("{label:<32}: {size} bytes");
    }

    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);

    let mut ik_initiator = IkHandshake::new_initiator(
        &crypto,
        initiator.clone(),
        responder.bundle(),
        TransportParams::default(),
    );
    let mut ik_responder =
        IkHandshake::new_responder(&crypto, responder.clone(), None, TransportParams::default());

    let ik1 = ik_initiator.write_1(&crypto, handshake_meta(101)).unwrap();
    ik_responder.read_1(&crypto, 0, &ik1).unwrap();

    let ik2 = ik_responder.write_2(&crypto, handshake_meta(101)).unwrap();
    ik_initiator.read_2(&crypto, 0, &ik2).unwrap();

    let ik1 = QlHandshakeRecord::Ik1(ik1);
    let ik2 = QlHandshakeRecord::Ik2(ik2);

    let mut kk_initiator = KkHandshake::new_initiator(
        &crypto,
        initiator.clone(),
        responder.bundle(),
        TransportParams::default(),
    );
    let mut kk_responder = KkHandshake::new_responder(
        &crypto,
        responder.clone(),
        initiator.bundle(),
        TransportParams::default(),
    );

    let kk1 = kk_initiator.write_1(&crypto, handshake_meta(201)).unwrap();
    kk_responder.read_1(&crypto, 0, &kk1).unwrap();

    let kk2 = kk_responder.write_2(&crypto, handshake_meta(201)).unwrap();
    kk_initiator.read_2(&crypto, 0, &kk2).unwrap();

    let kk1 = QlHandshakeRecord::Kk1(kk1);
    let kk2 = QlHandshakeRecord::Kk2(kk2);

    let token = pairing_token(0x42);
    let mut xx_initiator = XxHandshake::new_initiator(
        &crypto,
        initiator.clone(),
        token,
        TransportParams::default(),
    );
    let mut xx_responder = XxHandshake::new_responder(
        &crypto,
        responder.clone(),
        token,
        TransportParams::default(),
    );

    let xx1 = xx_initiator.write_1(&crypto, handshake_meta(301)).unwrap();
    xx_responder.read_1(&crypto, 0, &xx1).unwrap();

    let xx2 = xx_responder.write_2(&crypto, handshake_meta(301)).unwrap();
    xx_initiator.read_2(&crypto, 0, &xx2).unwrap();

    let xx3 = xx_initiator.write_3(&crypto, handshake_meta(301)).unwrap();
    xx_responder.read_3(&crypto, 0, &xx3).unwrap();

    let xx4 = xx_responder.write_4(&crypto, handshake_meta(301)).unwrap();
    xx_initiator.read_4(&crypto, 0, &xx4).unwrap();

    let xx1 = QlHandshakeRecord::Xx1(xx1);
    let xx2 = QlHandshakeRecord::Xx2(xx2);
    let xx3 = QlHandshakeRecord::Xx3(xx3);
    let xx4 = QlHandshakeRecord::Xx4(xx4);

    let session = ik_initiator.finalize(&crypto).unwrap();
    let session_ping = encrypt_record(
        &crypto,
        SessionHeader {
            connection_id: session.tx_connection_id,
            seq: record_seq(1),
        },
        &session.tx_key,
        &[SessionFrame::Ping],
    );
    let session_ack = encrypt_record(
        &crypto,
        SessionHeader {
            connection_id: session.tx_connection_id,
            seq: record_seq(2),
        },
        &session.tx_key,
        &[SessionFrame::Ack(
            RecordAck::from_ranges([record_ack_range(6, 6), record_ack_range(1, 2)]).unwrap(),
        )],
    );
    let session_stream_empty = encrypt_record(
        &crypto,
        SessionHeader {
            connection_id: session.tx_connection_id,
            seq: record_seq(3),
        },
        &session.tx_key,
        &[SessionFrame::StreamData(StreamData {
            stream_id: stream_id(1),
            offset: varint(0),
            header: None,
            fin: false,
            bytes: Vec::new(),
        })],
    );
    let session_close = encrypt_record(
        &crypto,
        SessionHeader {
            connection_id: session.tx_connection_id,
            seq: record_seq(4),
        },
        &session.tx_key,
        &[SessionFrame::Close(SessionClose {
            code: SessionCloseCode::PROTOCOL,
        })],
    );

    print_size("ql-wire peer bundle", initiator.bundle().encode_vec().len());
    print_size("ql-wire mlkem public key", MlKemPublicKey::SIZE);
    print_size("ql-wire mlkem ciphertext", MlKemCiphertext::SIZE);
    print_size("ql-wire pq ik1", ik1.encode_vec().len());
    print_size("ql-wire pq ik2", ik2.encode_vec().len());
    print_size("ql-wire pq kk1", kk1.encode_vec().len());
    print_size("ql-wire pq kk2", kk2.encode_vec().len());
    print_size("ql-wire pq xx1", xx1.encode_vec().len());
    print_size("ql-wire pq xx2", xx2.encode_vec().len());
    print_size("ql-wire pq xx3", xx3.encode_vec().len());
    print_size("ql-wire pq xx4", xx4.encode_vec().len());
    print_size("ql-wire session ping", session_ping.encode_vec().len());
    print_size("ql-wire session ack", session_ack.encode_vec().len());
    print_size(
        "ql-wire session stream empty",
        session_stream_empty.encode_vec().len(),
    );
    print_size("ql-wire session close", session_close.encode_vec().len());
}
