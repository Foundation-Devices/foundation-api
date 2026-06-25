use std::ops::RangeInclusive;

use ql_common::{ResetCode, StreamId, VarInt, QID};

use super::*;

fn decode_handshake_record(bytes: &[u8]) -> QlHandshakeRecord {
    decode_record(bytes).unwrap().1
}

fn decode_session_record(bytes: &[u8]) -> QlSessionRecord<Vec<u8>> {
    let (_, record) = decode_record::<QlSessionRecord<_>, _>(bytes).unwrap();
    record.into_owned()
}

fn varint(value: u64) -> VarInt {
    VarInt::from_u64(value).unwrap()
}

fn record_ack_range(start: u64, end: u64) -> RangeInclusive<RecordSeq> {
    RecordSeq(varint(start))..=RecordSeq(varint(end))
}

fn handshake_meta(id: u32) -> HandshakeMeta {
    HandshakeMeta {
        handshake_id: HandshakeId(id),
    }
}

fn handshake_transport_params(window: u32) -> TransportParams {
    TransportParams {
        initial_stream_receive_window: window,
    }
}

fn route(sender: u8, recipient: u8) -> RouteHeader {
    RouteHeader {
        sender: QID([sender; QID::SIZE]),
        recipient: QID([recipient; QID::SIZE]),
    }
}

fn identity_routes(a: &QlIdentity, b: &QlIdentity) -> (RouteHeader, RouteHeader) {
    (
        RouteHeader {
            sender: a.qid,
            recipient: b.qid,
        },
        RouteHeader {
            sender: b.qid,
            recipient: a.qid,
        },
    )
}

fn encrypt_record(
    crypto: &impl QlCrypto,
    route: RouteHeader,
    header: SessionHeader,
    session_key: &SessionKey,
    body: &[SessionFrame<Vec<u8>>],
) -> QlSessionRecord<Vec<u8>> {
    let mut builder = SessionRecordBuilder::new(header.seq, usize::MAX);
    for frame in body {
        let pushed = builder.push_frame(frame);
        debug_assert!(pushed);
    }
    decode_session_record(builder.encrypt(crypto, route, session_key).as_slice())
}

#[test]
fn peer_bundle_round_trip() {
    let crypto = SoftwareCrypto;
    let mut identity = generate_identity(&crypto, "alice").unwrap();
    identity.capabilities = 1231;
    let bundle = identity.bundle();

    let encoded = bundle.encode_vec();
    let decoded = PeerBundle::decode_exact(encoded.as_slice()).unwrap();

    assert_eq!(decoded, bundle);
    assert_eq!(&*decoded.name, "alice");
}

#[test]
fn identity_name_validation() {
    assert_eq!(
        QlName::new("a".repeat(QlName::MAX_LEN)).unwrap().len(),
        QlName::MAX_LEN
    );
    assert!(matches!(QlName::new(""), Err(WireError::InvalidPayload)));
    assert!(matches!(
        QlName::new("a".repeat(QlName::MAX_LEN + 1)),
        Err(WireError::InvalidPayload)
    ));
}

#[test]
fn handshake_record_round_trip_supports_ik_kk_and_xx() {
    let ik = QlHandshakeRecord::Ik1(Ik1 {
        meta: handshake_meta(1),
        transport_params: handshake_transport_params(65_536),
        skem_ciphertext: MlKemCiphertext::new(Box::new([7; MlKemCiphertext::SIZE])),
        ephemeral: EphemeralPublicKey {
            mlkem_public_key: MlKemPublicKey::new(Box::new([9; MlKemPublicKey::SIZE])),
        },
        static_bundle: EncryptedPeerBundle(vec![13; 64].into_boxed_slice()),
    });
    let ik_route = route(1, 2);
    let ik_encoded = encode_record_vec(RecordHeader::new(ik_route, RecordType::Handshake), &ik);
    assert_eq!(
        RecordHeader::decode_bytes(ik_encoded.as_slice()).unwrap(),
        RecordHeader {
            version: QL_WIRE_VERSION,
            route: ik_route,
            record_type: RecordType::Handshake,
        }
    );
    assert_eq!(decode_handshake_record(ik_encoded.as_slice()), ik);

    let kk = QlHandshakeRecord::Kk1(Kk1 {
        meta: handshake_meta(2),
        transport_params: handshake_transport_params(131_072),
        skem_ciphertext: MlKemCiphertext::new(Box::new([11; MlKemCiphertext::SIZE])),
        ephemeral: EphemeralPublicKey {
            mlkem_public_key: MlKemPublicKey::new(Box::new([15; MlKemPublicKey::SIZE])),
        },
    });
    let kk_route = route(1, 2);
    let kk_encoded = encode_record_vec(RecordHeader::new(kk_route, RecordType::Handshake), &kk);
    assert_eq!(
        RecordHeader::decode_bytes(kk_encoded.as_slice()).unwrap(),
        RecordHeader {
            version: QL_WIRE_VERSION,
            route: kk_route,
            record_type: RecordType::Handshake,
        }
    );
    assert_eq!(decode_handshake_record(kk_encoded.as_slice()), kk);

    let xx = QlHandshakeRecord::Xx1(Xx1 {
        meta: handshake_meta(3),
        pairing_id: PairingId([3; PairingId::SIZE]),
        transport_params: handshake_transport_params(196_608),
        ephemeral: EphemeralPublicKey {
            mlkem_public_key: MlKemPublicKey::new(Box::new([17; MlKemPublicKey::SIZE])),
        },
    });
    let xx_route = route(1, 2);
    let xx_encoded = encode_record_vec(RecordHeader::new(xx_route, RecordType::Handshake), &xx);
    assert_eq!(
        RecordHeader::decode_bytes(xx_encoded.as_slice()).unwrap(),
        RecordHeader {
            version: QL_WIRE_VERSION,
            route: xx_route,
            record_type: RecordType::Handshake,
        }
    );
    assert_eq!(decode_handshake_record(xx_encoded.as_slice()), xx);
}

#[test]
fn ik_handshake_rejects_tampered_handshake_meta() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let (initiator_to_responder, responder_to_initiator) = identity_routes(&initiator, &responder);

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
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let mut m2 = responder_state
        .write_2(&crypto, handshake_meta(77))
        .unwrap();
    m2.meta.handshake_id = HandshakeId(78);

    assert_eq!(
        initiator_state.read_2(&crypto, responder_to_initiator, &m2),
        Err(WireError::InvalidHandshakeMeta)
    );
}

#[test]
fn kk_handshake_rejects_tampered_handshake_header() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let (initiator_to_responder, _) = identity_routes(&initiator, &responder);

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
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let m2 = responder_state
        .write_2(&crypto, handshake_meta(88))
        .unwrap();
    let tampered_route = route(9, 1);

    assert_eq!(
        initiator_state.read_2(&crypto, tampered_route, &m2),
        Err(WireError::InvalidPayload)
    );
}

#[test]
fn ik_handshake_rejects_tampered_transport_params() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let (initiator_to_responder, responder_to_initiator) = identity_routes(&initiator, &responder);

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
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let mut m2 = responder_state
        .write_2(&crypto, handshake_meta(89))
        .unwrap();
    m2.transport_params.initial_stream_receive_window += 1;

    assert_eq!(
        initiator_state.read_2(&crypto, responder_to_initiator, &m2),
        Err(WireError::DecryptFailed)
    );
}

#[test]
fn ik_handshake_rejects_tampered_handshake_header() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let (mut initiator_to_responder, _) = identity_routes(&initiator, &responder);

    let mut initiator_state = IkHandshake::new_initiator(
        &crypto,
        initiator,
        responder.bundle(),
        TransportParams::default(),
    );
    let mut responder_state =
        IkHandshake::new_responder(&crypto, responder, None, TransportParams::default());

    let m1 = initiator_state
        .write_1(&crypto, handshake_meta(90))
        .unwrap();
    initiator_to_responder.sender = QID([9; QID::SIZE]);

    assert_eq!(
        responder_state.read_1(&crypto, initiator_to_responder, &m1),
        Err(WireError::DecryptFailed)
    );
}

#[test]
fn ik_handshake_rejects_bound_remote_bundle_mismatch() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let bogus = generate_identity(&crypto, "bogus").unwrap();
    let (initiator_to_responder, _) = identity_routes(&initiator, &responder);

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
        responder_state.read_1(&crypto, initiator_to_responder, &m1),
        Err(WireError::InvalidPayload)
    );
}

#[test]
fn ik_handshake_round_trip_derives_matching_transport_and_learns_remote() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let (initiator_to_responder, responder_to_initiator) = identity_routes(&initiator, &responder);

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
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let m2 = responder_state
        .write_2(&crypto, handshake_meta(11))
        .unwrap();
    initiator_state
        .read_2(&crypto, responder_to_initiator, &m2)
        .unwrap();

    let initiator_final = initiator_state.finalize(&crypto).unwrap();
    let responder_final = responder_state.finalize(&crypto).unwrap();

    assert_eq!(
        initiator_final.handshake_hash,
        responder_final.handshake_hash
    );
    assert_eq!(initiator_final.tx_key, responder_final.rx_key);
    assert_eq!(initiator_final.rx_key, responder_final.tx_key);
    assert_eq!(initiator_final.remote_bundle, responder.bundle());
    assert_eq!(responder_final.remote_bundle, initiator.bundle());
    assert_eq!(initiator_final.remote_transport_params, responder_params);
    assert_eq!(responder_final.remote_transport_params, initiator_params);
}

#[test]
fn ik_handshake_round_trip_derives_matching_transport_with_bound_responder() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let (initiator_to_responder, responder_to_initiator) = identity_routes(&initiator, &responder);

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
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let m2 = responder_state
        .write_2(&crypto, handshake_meta(12))
        .unwrap();
    initiator_state
        .read_2(&crypto, responder_to_initiator, &m2)
        .unwrap();

    let initiator_final = initiator_state.finalize(&crypto).unwrap();
    let responder_final = responder_state.finalize(&crypto).unwrap();

    assert_eq!(
        initiator_final.handshake_hash,
        responder_final.handshake_hash
    );
    assert_eq!(initiator_final.tx_key, responder_final.rx_key);
    assert_eq!(initiator_final.rx_key, responder_final.tx_key);
    assert_eq!(initiator_final.remote_bundle, responder.bundle());
    assert_eq!(responder_final.remote_bundle, initiator.bundle());
    assert_eq!(initiator_final.remote_transport_params, responder_params);
    assert_eq!(responder_final.remote_transport_params, initiator_params);
}

#[test]
fn kk_handshake_round_trip_derives_matching_transport() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let (initiator_to_responder, responder_to_initiator) = identity_routes(&initiator, &responder);

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
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let m2 = responder_state
        .write_2(&crypto, handshake_meta(21))
        .unwrap();
    initiator_state
        .read_2(&crypto, responder_to_initiator, &m2)
        .unwrap();

    let initiator_final = initiator_state.finalize(&crypto).unwrap();
    let responder_final = responder_state.finalize(&crypto).unwrap();

    assert_eq!(
        initiator_final.handshake_hash,
        responder_final.handshake_hash
    );
    assert_eq!(initiator_final.tx_key, responder_final.rx_key);
    assert_eq!(initiator_final.rx_key, responder_final.tx_key);
    assert_eq!(initiator_final.remote_bundle, responder.bundle());
    assert_eq!(responder_final.remote_bundle, initiator.bundle());
    assert_eq!(initiator_final.remote_transport_params, responder_params);
    assert_eq!(responder_final.remote_transport_params, initiator_params);
}

#[test]
fn kk_handshake_rejects_tampered_transport_params() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let (initiator_to_responder, responder_to_initiator) = identity_routes(&initiator, &responder);

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
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let mut m2 = responder_state
        .write_2(&crypto, handshake_meta(22))
        .unwrap();
    m2.transport_params.initial_stream_receive_window += 1;

    assert_eq!(
        initiator_state.read_2(&crypto, responder_to_initiator, &m2),
        Err(WireError::DecryptFailed)
    );
}

#[test]
fn xx_handshake_rejects_tampered_pairing_id() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let token = PairingToken([7; PairingToken::SIZE]);
    let (initiator_to_responder, _) = identity_routes(&initiator, &responder);

    let mut initiator_state = XxHandshake::new_initiator(
        &crypto,
        initiator.clone(),
        responder.qid,
        token,
        TransportParams::default(),
    );
    let mut responder_state = XxHandshake::new_responder(
        &crypto,
        responder,
        initiator.qid,
        token,
        TransportParams::default(),
    );

    let mut m1 = initiator_state
        .write_1(&crypto, handshake_meta(31))
        .unwrap();
    m1.pairing_id = PairingId([8; PairingId::SIZE]);

    assert_eq!(
        responder_state.read_1(&crypto, initiator_to_responder, &m1),
        Err(WireError::InvalidPairingId)
    );
}

#[test]
fn xx_handshake_rejects_tampered_sender_or_recipient() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let token = PairingToken([7; PairingToken::SIZE]);

    let mut initiator_state = XxHandshake::new_initiator(
        &crypto,
        initiator.clone(),
        responder.qid,
        token,
        TransportParams::default(),
    );
    let mut responder_state = XxHandshake::new_responder(
        &crypto,
        responder.clone(),
        initiator.qid,
        token,
        TransportParams::default(),
    );

    let m1 = initiator_state
        .write_1(&crypto, handshake_meta(31))
        .unwrap();
    let (mut route, _) = identity_routes(&initiator, &responder);
    route.sender = responder.qid;

    assert_eq!(
        responder_state.read_1(&crypto, route, &m1),
        Err(WireError::InvalidRouteHeader)
    );

    let mut initiator_state = XxHandshake::new_initiator(
        &crypto,
        initiator.clone(),
        responder.qid,
        token,
        TransportParams::default(),
    );
    let mut responder_state = XxHandshake::new_responder(
        &crypto,
        responder.clone(),
        initiator.qid,
        token,
        TransportParams::default(),
    );

    let m1 = initiator_state
        .write_1(&crypto, handshake_meta(31))
        .unwrap();
    let (mut route, _) = identity_routes(&initiator, &responder);
    route.recipient = initiator.qid;

    assert_eq!(
        responder_state.read_1(&crypto, route, &m1),
        Err(WireError::InvalidRouteHeader)
    );
}

#[test]
fn xx_handshake_rejects_repeated_transport_param_change() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let token = PairingToken([9; PairingToken::SIZE]);
    let (initiator_to_responder, responder_to_initiator) = identity_routes(&initiator, &responder);

    let mut initiator_state = XxHandshake::new_initiator(
        &crypto,
        initiator.clone(),
        responder.qid,
        token,
        handshake_transport_params(12_288),
    );
    let mut responder_state = XxHandshake::new_responder(
        &crypto,
        responder,
        initiator.qid,
        token,
        handshake_transport_params(24_576),
    );

    let m1 = initiator_state
        .write_1(&crypto, handshake_meta(32))
        .unwrap();
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let m2 = responder_state
        .write_2(&crypto, handshake_meta(32))
        .unwrap();
    initiator_state
        .read_2(&crypto, responder_to_initiator, &m2)
        .unwrap();

    let mut m3 = initiator_state
        .write_3(&crypto, handshake_meta(32))
        .unwrap();
    m3.transport_params.initial_stream_receive_window += 1;

    assert_eq!(
        responder_state.read_3(&crypto, initiator_to_responder, &m3),
        Err(WireError::InvalidTransportParams)
    );
}

#[test]
fn xx_handshake_round_trip_derives_matching_transport_and_learns_remote() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let token = PairingToken([10; PairingToken::SIZE]);
    let (initiator_to_responder, responder_to_initiator) = identity_routes(&initiator, &responder);

    let initiator_params = handshake_transport_params(28_672);
    let responder_params = handshake_transport_params(57_344);
    let mut initiator_state = XxHandshake::new_initiator(
        &crypto,
        initiator.clone(),
        responder.qid,
        token,
        initiator_params,
    );
    let mut responder_state = XxHandshake::new_responder(
        &crypto,
        responder.clone(),
        initiator.qid,
        token,
        responder_params,
    );

    assert_eq!(initiator_state.pairing_token(), token);
    assert_eq!(responder_state.pairing_token(), token);
    assert_eq!(initiator_state.pairing_id(&crypto), token.id(&crypto));
    assert_eq!(responder_state.pairing_id(&crypto), token.id(&crypto));
    assert!(initiator_state.remote_bundle().is_none());
    assert!(responder_state.remote_bundle().is_none());

    let m1 = initiator_state
        .write_1(&crypto, handshake_meta(33))
        .unwrap();
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let m2 = responder_state
        .write_2(&crypto, handshake_meta(33))
        .unwrap();
    initiator_state
        .read_2(&crypto, responder_to_initiator, &m2)
        .unwrap();
    assert_eq!(initiator_state.remote_bundle(), Some(&responder.bundle()));
    assert!(responder_state.remote_bundle().is_none());

    let m3 = initiator_state
        .write_3(&crypto, handshake_meta(33))
        .unwrap();
    responder_state
        .read_3(&crypto, initiator_to_responder, &m3)
        .unwrap();
    assert_eq!(responder_state.remote_bundle(), Some(&initiator.bundle()));

    let m4 = responder_state
        .write_4(&crypto, handshake_meta(33))
        .unwrap();
    initiator_state
        .read_4(&crypto, responder_to_initiator, &m4)
        .unwrap();

    let initiator_final = initiator_state.finalize(&crypto).unwrap();
    let responder_final = responder_state.finalize(&crypto).unwrap();

    assert_eq!(
        initiator_final.handshake_hash,
        responder_final.handshake_hash
    );
    assert_eq!(initiator_final.tx_key, responder_final.rx_key);
    assert_eq!(initiator_final.rx_key, responder_final.tx_key);
    assert_eq!(initiator_final.remote_bundle, responder.bundle());
    assert_eq!(responder_final.remote_bundle, initiator.bundle());
    assert_eq!(initiator_final.remote_transport_params, responder_params);
    assert_eq!(responder_final.remote_transport_params, initiator_params);
}

#[test]
fn encrypted_session_record_round_trip_authenticates_header() {
    let crypto = SoftwareCrypto;
    let header = SessionHeader {
        seq: RecordSeq(varint(11)),
    };
    let session_route = route(1, 2);
    let body = vec![
        SessionFrame::Ping,
        SessionFrame::Unpair,
        SessionFrame::Ack(
            RecordAck::from_ranges([record_ack_range(20, 23), record_ack_range(12, 13)]).unwrap(),
        ),
        SessionFrame::StreamWindow(StreamWindow {
            stream_id: StreamId(varint(9)),
            maximum_offset: varint(65_536),
        }),
        SessionFrame::StreamData(StreamData {
            stream_id: StreamId(varint(9)),
            offset: varint(1024),
            header: None,
            bytes: b"hello".to_vec(),
            fin: true,
        }),
        SessionFrame::StreamReset(StreamReset {
            stream_id: StreamId(varint(9)),
            target: ResetTarget::Both,
            code: ResetCode::CANCELLED,
        }),
        SessionFrame::Close(SessionClose {
            code: SessionCloseCode::TIMEOUT,
        }),
    ];
    let session_key = SessionKey([7; SessionKey::SIZE]);
    let record = encrypt_record(&crypto, session_route, header, &session_key, &body);

    let record_header = RecordHeader::new(session_route, RecordType::Session);
    let bytes = encode_record_vec(record_header, &record);
    assert_eq!(
        RecordHeader::decode_bytes(bytes.as_slice()).unwrap(),
        RecordHeader {
            version: QL_WIRE_VERSION,
            route: session_route,
            record_type: RecordType::Session,
        }
    );
    let decoded = decode_session_record(bytes.as_slice());
    assert_eq!(decoded.header, header);
    let encrypted = decoded.payload;

    let decrypted = encrypted::decrypt_record(
        &crypto,
        &record_header,
        &header,
        encrypted.clone(),
        &session_key,
    )
    .unwrap();
    assert_eq!(decode_session_frames(&decrypted).unwrap(), body);

    let wrong_record_header = RecordHeader::new(route(2, 1), RecordType::Session);
    assert_eq!(
        encrypted::decrypt_record(
            &crypto,
            &wrong_record_header,
            &header,
            encrypted.clone(),
            &session_key,
        ),
        Err(WireError::DecryptFailed)
    );

    let wrong_seq_header = SessionHeader {
        seq: RecordSeq(varint(header.seq.0.into_inner() + 1)),
    };
    assert_eq!(
        encrypted::decrypt_record(
            &crypto,
            &record_header,
            &wrong_seq_header,
            encrypted,
            &session_key,
        ),
        Err(WireError::DecryptFailed)
    );
}

#[test]
fn protocol_record_size_breakdown() {
    fn print_size(label: &str, size: usize) {
        println!("{label:<32}: {size} bytes");
    }

    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let (initiator_to_responder, responder_to_initiator) = identity_routes(&initiator, &responder);

    let mut ik_initiator = IkHandshake::new_initiator(
        &crypto,
        initiator.clone(),
        responder.bundle(),
        TransportParams::default(),
    );
    let mut ik_responder =
        IkHandshake::new_responder(&crypto, responder.clone(), None, TransportParams::default());

    let ik1 = ik_initiator.write_1(&crypto, handshake_meta(101)).unwrap();
    ik_responder
        .read_1(&crypto, initiator_to_responder, &ik1)
        .unwrap();

    let ik2 = ik_responder.write_2(&crypto, handshake_meta(101)).unwrap();
    ik_initiator
        .read_2(&crypto, responder_to_initiator, &ik2)
        .unwrap();

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
    kk_responder
        .read_1(&crypto, initiator_to_responder, &kk1)
        .unwrap();

    let kk2 = kk_responder.write_2(&crypto, handshake_meta(201)).unwrap();
    kk_initiator
        .read_2(&crypto, responder_to_initiator, &kk2)
        .unwrap();

    let kk1 = QlHandshakeRecord::Kk1(kk1);
    let kk2 = QlHandshakeRecord::Kk2(kk2);

    let token = PairingToken([0x42; PairingToken::SIZE]);
    let mut xx_initiator = XxHandshake::new_initiator(
        &crypto,
        initiator.clone(),
        responder.qid,
        token,
        TransportParams::default(),
    );
    let mut xx_responder = XxHandshake::new_responder(
        &crypto,
        responder.clone(),
        initiator.qid,
        token,
        TransportParams::default(),
    );

    let xx1 = xx_initiator.write_1(&crypto, handshake_meta(301)).unwrap();
    xx_responder
        .read_1(&crypto, initiator_to_responder, &xx1)
        .unwrap();

    let xx2 = xx_responder.write_2(&crypto, handshake_meta(301)).unwrap();
    xx_initiator
        .read_2(&crypto, responder_to_initiator, &xx2)
        .unwrap();

    let xx3 = xx_initiator.write_3(&crypto, handshake_meta(301)).unwrap();
    xx_responder
        .read_3(&crypto, initiator_to_responder, &xx3)
        .unwrap();

    let xx4 = xx_responder.write_4(&crypto, handshake_meta(301)).unwrap();
    xx_initiator
        .read_4(&crypto, responder_to_initiator, &xx4)
        .unwrap();

    let xx1 = QlHandshakeRecord::Xx1(xx1);
    let xx2 = QlHandshakeRecord::Xx2(xx2);
    let xx3 = QlHandshakeRecord::Xx3(xx3);
    let xx4 = QlHandshakeRecord::Xx4(xx4);

    let session = ik_initiator.finalize(&crypto).unwrap();
    let session_route = RouteHeader {
        sender: initiator.qid,
        recipient: responder.qid,
    };
    let session_ping = encrypt_record(
        &crypto,
        session_route,
        SessionHeader {
            seq: RecordSeq(varint(1)),
        },
        &session.tx_key,
        &[SessionFrame::Ping],
    );
    let session_ack = encrypt_record(
        &crypto,
        session_route,
        SessionHeader {
            seq: RecordSeq(varint(2)),
        },
        &session.tx_key,
        &[SessionFrame::Ack(
            RecordAck::from_ranges([record_ack_range(6, 6), record_ack_range(1, 2)]).unwrap(),
        )],
    );
    let session_unpair = encrypt_record(
        &crypto,
        session_route,
        SessionHeader {
            seq: RecordSeq(varint(3)),
        },
        &session.tx_key,
        &[SessionFrame::Unpair],
    );
    let session_stream_empty = encrypt_record(
        &crypto,
        session_route,
        SessionHeader {
            seq: RecordSeq(varint(4)),
        },
        &session.tx_key,
        &[SessionFrame::StreamData(StreamData {
            stream_id: StreamId(varint(1)),
            offset: varint(0),
            header: None,
            fin: false,
            bytes: Vec::new(),
        })],
    );
    let session_close = encrypt_record(
        &crypto,
        session_route,
        SessionHeader {
            seq: RecordSeq(varint(5)),
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
    print_size("ql-wire session unpair", session_unpair.encode_vec().len());
    print_size(
        "ql-wire session stream empty",
        session_stream_empty.encode_vec().len(),
    );
    print_size("ql-wire session close", session_close.encode_vec().len());
}
