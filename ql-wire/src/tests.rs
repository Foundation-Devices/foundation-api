use ql_codec::{Decode, Encode, Varint};
use ql_common::{ResetCode, StreamId, QID};

use super::*;

fn decode_handshake_record(bytes: &[u8]) -> QlHandshakeRecord {
    decode_record(bytes).unwrap().1
}

fn decode_session_record(bytes: &[u8]) -> QlSessionRecord<Vec<u8>> {
    let (_, record) = decode_record::<QlSessionRecord<_>, _>(bytes).unwrap();
    record.into_owned()
}

fn handshake_id(id: u32) -> HandshakeId {
    HandshakeId(id)
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
    let mut identity = generate_identity(&crypto, "alice");
    identity.capabilities = 1231;
    let bundle = identity.bundle();

    let encoded = bundle.encode_vec();
    let decoded = PeerBundle::decode_bytes(encoded.as_slice()).unwrap();

    assert_eq!(decoded, bundle);
    assert_eq!(decoded.name, "alice");
}

#[test]
fn handshake_record_round_trip_supports_ik_kk_and_xx() {
    let ik = QlHandshakeRecord::Ik1(Ik1 {
        handshake_id: handshake_id(1),
        transport_params: handshake_transport_params(65_536),
        skem_ciphertext: MlKemCiphertext::new(Box::new([7; MlKemCiphertext::SIZE])),
        ephemeral: EphemeralPublicKey {
            mlkem_public_key: MlKemPublicKey::new(Box::new([9; MlKemPublicKey::SIZE])),
        },
        static_bundle: Some(EncryptedPeerBundle(vec![13; 64].into_boxed_slice())),
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

    let kk = QlHandshakeRecord::Kk1(Ik1 {
        handshake_id: handshake_id(2),
        transport_params: handshake_transport_params(131_072),
        skem_ciphertext: MlKemCiphertext::new(Box::new([11; MlKemCiphertext::SIZE])),
        ephemeral: EphemeralPublicKey {
            mlkem_public_key: MlKemPublicKey::new(Box::new([15; MlKemPublicKey::SIZE])),
        },
        static_bundle: None,
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
        handshake_id: handshake_id(3),
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
fn ik_handshake_rejects_tampered_handshake_id() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let (initiator_to_responder, responder_to_initiator) = identity_routes(&initiator, &responder);

    let mut initiator_state = IkHandshake::new_ik_initiator(
        &crypto,
        initiator,
        responder.bundle(),
        TransportParams::default(),
    );
    let mut responder_state =
        IkHandshake::new_ik_responder(&crypto, responder, None, TransportParams::default());

    let m1 = initiator_state.write_1(&crypto, handshake_id(77)).unwrap();
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let mut m2 = responder_state.write_2(&crypto, handshake_id(77)).unwrap();
    m2.handshake_id = HandshakeId(78);

    assert_eq!(
        initiator_state.read_2(&crypto, responder_to_initiator, &m2),
        Err(Error::InvalidHandshakeId)
    );
}

#[test]
fn kk_handshake_rejects_tampered_handshake_header() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let (initiator_to_responder, _) = identity_routes(&initiator, &responder);

    let mut initiator_state = IkHandshake::new_kk_initiator(
        &crypto,
        initiator.clone(),
        responder.bundle(),
        TransportParams::default(),
    );
    let mut responder_state = IkHandshake::new_kk_responder(
        &crypto,
        responder,
        initiator.bundle(),
        TransportParams::default(),
    );

    let m1 = initiator_state.write_1(&crypto, handshake_id(88)).unwrap();
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let m2 = responder_state.write_2(&crypto, handshake_id(88)).unwrap();
    let tampered_route = route(9, 1);

    assert_eq!(
        initiator_state.read_2(&crypto, tampered_route, &m2),
        Err(Error::InvalidRouteHeader)
    );
}

#[test]
fn ik_handshake_rejects_tampered_transport_params() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let (initiator_to_responder, responder_to_initiator) = identity_routes(&initiator, &responder);

    let mut initiator_state = IkHandshake::new_ik_initiator(
        &crypto,
        initiator,
        responder.bundle(),
        handshake_transport_params(4096),
    );
    let mut responder_state =
        IkHandshake::new_ik_responder(&crypto, responder, None, handshake_transport_params(8192));

    let m1 = initiator_state.write_1(&crypto, handshake_id(89)).unwrap();
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let mut m2 = responder_state.write_2(&crypto, handshake_id(89)).unwrap();
    m2.transport_params.initial_stream_receive_window += 1;

    assert_eq!(
        initiator_state.read_2(&crypto, responder_to_initiator, &m2),
        Err(Error::DecryptFailed)
    );
}

#[test]
fn ik_handshake_rejects_tampered_handshake_header() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let (mut initiator_to_responder, _) = identity_routes(&initiator, &responder);

    let mut initiator_state = IkHandshake::new_ik_initiator(
        &crypto,
        initiator,
        responder.bundle(),
        TransportParams::default(),
    );
    let mut responder_state =
        IkHandshake::new_ik_responder(&crypto, responder, None, TransportParams::default());

    let m1 = initiator_state.write_1(&crypto, handshake_id(90)).unwrap();
    initiator_to_responder.sender = QID([9; QID::SIZE]);

    assert_eq!(
        responder_state.read_1(&crypto, initiator_to_responder, &m1),
        Err(Error::DecryptFailed)
    );
}

#[test]
fn ik_handshake_rejects_bound_remote_bundle_mismatch() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let bogus = generate_identity(&crypto, "bogus");
    let (initiator_to_responder, _) = identity_routes(&initiator, &responder);

    let mut initiator_state = IkHandshake::new_ik_initiator(
        &crypto,
        initiator,
        responder.bundle(),
        TransportParams::default(),
    );
    let mut responder_state = IkHandshake::new_ik_responder(
        &crypto,
        responder,
        Some(bogus.bundle()),
        TransportParams::default(),
    );

    let m1 = initiator_state.write_1(&crypto, handshake_id(91)).unwrap();

    assert_eq!(
        responder_state.read_1(&crypto, initiator_to_responder, &m1),
        Err(Error::InvalidRouteHeader)
    );
}

#[test]
fn ik_handshake_round_trip_derives_matching_transport_and_learns_remote() {
    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let (initiator_to_responder, responder_to_initiator) = identity_routes(&initiator, &responder);

    let initiator_params = handshake_transport_params(4096);
    let responder_params = handshake_transport_params(8192);
    let mut initiator_state = IkHandshake::new_ik_initiator(
        &crypto,
        initiator.clone(),
        responder.bundle(),
        initiator_params,
    );
    let mut responder_state =
        IkHandshake::new_ik_responder(&crypto, responder.clone(), None, responder_params);

    let m1 = initiator_state.write_1(&crypto, handshake_id(11)).unwrap();
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let m2 = responder_state.write_2(&crypto, handshake_id(11)).unwrap();
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
    let mut initiator_state = IkHandshake::new_ik_initiator(
        &crypto,
        initiator.clone(),
        responder.bundle(),
        initiator_params,
    );
    let mut responder_state = IkHandshake::new_ik_responder(
        &crypto,
        responder.clone(),
        Some(initiator.bundle()),
        responder_params,
    );

    let m1 = initiator_state.write_1(&crypto, handshake_id(12)).unwrap();
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let m2 = responder_state.write_2(&crypto, handshake_id(12)).unwrap();
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
    let mut initiator_state = IkHandshake::new_kk_initiator(
        &crypto,
        initiator.clone(),
        responder.bundle(),
        initiator_params,
    );
    let mut responder_state = IkHandshake::new_kk_responder(
        &crypto,
        responder.clone(),
        initiator.bundle(),
        responder_params,
    );

    let m1 = initiator_state.write_1(&crypto, handshake_id(21)).unwrap();
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let m2 = responder_state.write_2(&crypto, handshake_id(21)).unwrap();
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

    let mut initiator_state = IkHandshake::new_kk_initiator(
        &crypto,
        initiator.clone(),
        responder.bundle(),
        handshake_transport_params(12288),
    );
    let mut responder_state = IkHandshake::new_kk_responder(
        &crypto,
        responder,
        initiator.bundle(),
        handshake_transport_params(24576),
    );

    let m1 = initiator_state.write_1(&crypto, handshake_id(22)).unwrap();
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let mut m2 = responder_state.write_2(&crypto, handshake_id(22)).unwrap();
    m2.transport_params.initial_stream_receive_window += 1;

    assert_eq!(
        initiator_state.read_2(&crypto, responder_to_initiator, &m2),
        Err(Error::DecryptFailed)
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

    let mut m1 = initiator_state.write_1(&crypto, handshake_id(31)).unwrap();
    m1.pairing_id = PairingId([8; PairingId::SIZE]);

    assert_eq!(
        responder_state.read_1(&crypto, initiator_to_responder, &m1),
        Err(Error::InvalidPairingId)
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

    let m1 = initiator_state.write_1(&crypto, handshake_id(31)).unwrap();
    let (mut route, _) = identity_routes(&initiator, &responder);
    route.sender = responder.qid;

    assert_eq!(
        responder_state.read_1(&crypto, route, &m1),
        Err(Error::InvalidRouteHeader)
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

    let m1 = initiator_state.write_1(&crypto, handshake_id(31)).unwrap();
    let (mut route, _) = identity_routes(&initiator, &responder);
    route.recipient = initiator.qid;

    assert_eq!(
        responder_state.read_1(&crypto, route, &m1),
        Err(Error::InvalidRouteHeader)
    );
}

#[test]
fn xx_handshake_rejects_tampered_transport_params() {
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

    let m1 = initiator_state.write_1(&crypto, handshake_id(32)).unwrap();
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let mut m2 = responder_state.write_2(&crypto, handshake_id(32)).unwrap();
    m2.transport_params.initial_stream_receive_window += 1;

    assert_eq!(
        initiator_state.read_2(&crypto, responder_to_initiator, &m2),
        Err(Error::DecryptFailed)
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

    let m1 = initiator_state.write_1(&crypto, handshake_id(33)).unwrap();
    responder_state
        .read_1(&crypto, initiator_to_responder, &m1)
        .unwrap();

    let m2 = responder_state.write_2(&crypto, handshake_id(33)).unwrap();
    initiator_state
        .read_2(&crypto, responder_to_initiator, &m2)
        .unwrap();
    assert_eq!(initiator_state.remote_bundle(), Some(&responder.bundle()));
    assert!(responder_state.remote_bundle().is_none());

    let m3 = initiator_state.write_3(&crypto, handshake_id(33)).unwrap();
    responder_state
        .read_3(&crypto, initiator_to_responder, &m3)
        .unwrap();
    assert_eq!(responder_state.remote_bundle(), Some(&initiator.bundle()));

    let m4 = responder_state.write_4(&crypto, handshake_id(33)).unwrap();
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
    let header = SessionHeader { seq: RecordSeq(11) };
    let session_route = route(1, 2);
    let body = vec![
        SessionFrame::Ping,
        SessionFrame::Unpair,
        SessionFrame::Ack(
            RecordAck::from_ranges([RecordSeq(20)..=RecordSeq(23), RecordSeq(12)..=RecordSeq(13)])
                .unwrap(),
        ),
        SessionFrame::StreamWindow(StreamWindow {
            stream_id: StreamId(9),
            maximum_offset: Varint(65_536),
        }),
        SessionFrame::StreamData(StreamData {
            stream_id: StreamId(9),
            offset: Varint(0),
            open: Some(StreamOpen {
                header: b"route".to_vec(),
                receive_window: Varint(32 * 1024),
                requested_peer_receive_window: Varint(24 * 1024),
            }),
            bytes: b"hello".to_vec(),
            fin: true,
        }),
        SessionFrame::StreamReset(StreamReset {
            stream_id: StreamId(9),
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
        Err(Error::DecryptFailed)
    );

    let wrong_seq_header = SessionHeader {
        seq: RecordSeq(header.seq.0 + 1),
    };
    assert_eq!(
        encrypted::decrypt_record(
            &crypto,
            &record_header,
            &wrong_seq_header,
            encrypted,
            &session_key,
        ),
        Err(Error::DecryptFailed)
    );
}

#[test]
fn protocol_record_size_breakdown() {
    fn print_size(label: &str, size: usize) {
        println!("{label:<32}: {size} bytes");
    }

    fn record_size(record: &impl Encode) -> usize {
        RecordHeader::WIRE_SIZE + record.encoded_len()
    }

    let crypto = SoftwareCrypto;
    let (initiator, responder) = test_identities(&crypto);
    let (initiator_to_responder, responder_to_initiator) = identity_routes(&initiator, &responder);

    let mut ik_initiator = IkHandshake::new_ik_initiator(
        &crypto,
        initiator.clone(),
        responder.bundle(),
        TransportParams::default(),
    );
    let mut ik_responder =
        IkHandshake::new_ik_responder(&crypto, responder.clone(), None, TransportParams::default());

    let ik1 = ik_initiator.write_1(&crypto, handshake_id(101)).unwrap();
    ik_responder
        .read_1(&crypto, initiator_to_responder, &ik1)
        .unwrap();

    let ik2 = ik_responder.write_2(&crypto, handshake_id(101)).unwrap();
    ik_initiator
        .read_2(&crypto, responder_to_initiator, &ik2)
        .unwrap();

    let ik1 = QlHandshakeRecord::Ik1(ik1);
    let ik2 = QlHandshakeRecord::Ik2(ik2);

    let mut kk_initiator = IkHandshake::new_kk_initiator(
        &crypto,
        initiator.clone(),
        responder.bundle(),
        TransportParams::default(),
    );
    let mut kk_responder = IkHandshake::new_kk_responder(
        &crypto,
        responder.clone(),
        initiator.bundle(),
        TransportParams::default(),
    );

    let kk1 = kk_initiator.write_1(&crypto, handshake_id(201)).unwrap();
    kk_responder
        .read_1(&crypto, initiator_to_responder, &kk1)
        .unwrap();

    let kk2 = kk_responder.write_2(&crypto, handshake_id(201)).unwrap();
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

    let xx1 = xx_initiator.write_1(&crypto, handshake_id(301)).unwrap();
    xx_responder
        .read_1(&crypto, initiator_to_responder, &xx1)
        .unwrap();

    let xx2 = xx_responder.write_2(&crypto, handshake_id(301)).unwrap();
    xx_initiator
        .read_2(&crypto, responder_to_initiator, &xx2)
        .unwrap();

    let xx3 = xx_initiator.write_3(&crypto, handshake_id(301)).unwrap();
    xx_responder
        .read_3(&crypto, initiator_to_responder, &xx3)
        .unwrap();

    let xx4 = xx_responder.write_4(&crypto, handshake_id(301)).unwrap();
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
        SessionHeader { seq: RecordSeq(1) },
        &session.tx_key,
        &[SessionFrame::Ping],
    );
    let session_ack = encrypt_record(
        &crypto,
        session_route,
        SessionHeader { seq: RecordSeq(2) },
        &session.tx_key,
        &[SessionFrame::Ack(
            RecordAck::from_ranges([RecordSeq(6)..=RecordSeq(6), RecordSeq(1)..=RecordSeq(2)])
                .unwrap(),
        )],
    );
    let session_unpair = encrypt_record(
        &crypto,
        session_route,
        SessionHeader { seq: RecordSeq(3) },
        &session.tx_key,
        &[SessionFrame::Unpair],
    );
    let session_stream_empty = encrypt_record(
        &crypto,
        session_route,
        SessionHeader { seq: RecordSeq(4) },
        &session.tx_key,
        &[SessionFrame::StreamData(StreamData {
            stream_id: StreamId(1),
            offset: Varint(0),
            open: None,
            fin: false,
            bytes: Vec::new(),
        })],
    );
    let session_close = encrypt_record(
        &crypto,
        session_route,
        SessionHeader { seq: RecordSeq(5) },
        &session.tx_key,
        &[SessionFrame::Close(SessionClose {
            code: SessionCloseCode::PROTOCOL,
        })],
    );

    print_size("ql-wire peer bundle", initiator.bundle().encode_vec().len());
    print_size("ql-wire mlkem public key", MlKemPublicKey::SIZE);
    print_size("ql-wire mlkem ciphertext", MlKemCiphertext::SIZE);
    print_size("ql-wire pq ik1", record_size(&ik1));
    print_size("ql-wire pq ik2", record_size(&ik2));
    print_size("ql-wire pq kk1", record_size(&kk1));
    print_size("ql-wire pq kk2", record_size(&kk2));
    print_size("ql-wire pq xx1", record_size(&xx1));
    print_size("ql-wire pq xx2", record_size(&xx2));
    print_size("ql-wire pq xx3", record_size(&xx3));
    print_size("ql-wire pq xx4", record_size(&xx4));
    print_size("ql-wire session ping", record_size(&session_ping));
    print_size("ql-wire session ack", record_size(&session_ack));
    print_size("ql-wire session unpair", record_size(&session_unpair));
    print_size(
        "ql-wire session stream empty",
        record_size(&session_stream_empty),
    );
    print_size("ql-wire session close", record_size(&session_close));
}

/// `encode_vec` asserts the buffer ends up `encoded_len()` long, so encoding is the check.
fn assert_encoded_len<T: Encode>(label: &str, value: &T) {
    let encoded = value.encode_vec();
    assert_eq!(encoded.len(), value.encoded_len(), "{label}");
}

fn mlkem_public_key() -> MlKemPublicKey {
    MlKemPublicKey::new(Box::new([7u8; MlKemPublicKey::SIZE]))
}

fn mlkem_ciphertext() -> MlKemCiphertext {
    MlKemCiphertext::new(Box::new([9u8; MlKemCiphertext::SIZE]))
}

fn encrypted_mlkem_ciphertext() -> EncryptedMlKemCiphertext {
    EncryptedMlKemCiphertext::new(Box::new([3u8; EncryptedMlKemCiphertext::SIZE]))
}

fn encrypted_peer_bundle() -> EncryptedPeerBundle {
    EncryptedPeerBundle(Box::from(&[1u8, 2, 3, 4, 5][..]))
}

fn ephemeral_public_key() -> EphemeralPublicKey {
    EphemeralPublicKey {
        mlkem_public_key: mlkem_public_key(),
    }
}

#[test]
fn encoded_len_matches_encoding() {
    let params = handshake_transport_params(1024);

    assert_encoded_len("QID", &QID([1u8; QID::SIZE]));
    assert_encoded_len("HandshakeId", &handshake_id(0xdead_beef));
    assert_encoded_len("PairingId", &PairingId([4u8; PairingId::SIZE]));
    assert_encoded_len("SessionKey", &SessionKey([5u8; SessionKey::SIZE]));
    assert_encoded_len("MlKemPublicKey", &mlkem_public_key());
    assert_encoded_len("MlKemCiphertext", &mlkem_ciphertext());
    assert_encoded_len("EncryptedMlKemCiphertext", &encrypted_mlkem_ciphertext());
    assert_encoded_len("EncryptedPeerBundle", &encrypted_peer_bundle());
    assert_encoded_len("EphemeralPublicKey", &ephemeral_public_key());
    assert_encoded_len("TransportParams", &params);
    assert_encoded_len("RouteHeader", &route(1, 2));
    assert_encoded_len(
        "RecordHeader",
        &RecordHeader::new(route(1, 2), RecordType::Handshake),
    );
    assert_encoded_len("RecordType", &RecordType::Session);
    assert_encoded_len("HandshakeKind", &HandshakeKind::Xx4);
    assert_encoded_len("SessionHeader", &SessionHeader { seq: RecordSeq(7) });
    assert_encoded_len("ResetTarget", &ResetTarget::Both);
    assert_encoded_len(
        "PeerBundle",
        &PeerBundle {
            version: 1,
            qid: QID([3u8; QID::SIZE]),
            capabilities: 0xffff_ffff,
            mlkem_public_key: mlkem_public_key(),
            name: "device".to_owned(),
        },
    );
    assert_encoded_len(
        "StreamReset",
        &StreamReset {
            stream_id: StreamId(9),
            target: ResetTarget::Origin,
            code: ResetCode::TIMEOUT,
        },
    );
    assert_encoded_len(
        "StreamWindow",
        &StreamWindow {
            stream_id: StreamId(9),
            maximum_offset: Varint(1 << 40),
        },
    );
    assert_encoded_len(
        "StreamData",
        &StreamData {
            stream_id: StreamId(9),
            offset: Varint(0),
            open: Some(StreamOpen {
                header: b"route".as_slice(),
                receive_window: Varint(32 * 1024),
                requested_peer_receive_window: Varint(24 * 1024),
            }),
            fin: false,
            bytes: b"payload".as_slice(),
        },
    );
    assert_encoded_len(
        "SessionClose",
        &SessionClose {
            code: SessionCloseCode::PROTOCOL,
        },
    );
    let payload = EncryptedMessage {
        auth: [6u8; ENCRYPTED_MESSAGE_AUTH_SIZE],
        ciphertext: vec![21u8; 37],
    };
    assert_encoded_len("EncryptedMessage", &payload);
    assert_encoded_len(
        "QlSessionRecord",
        &QlSessionRecord {
            header: SessionHeader { seq: RecordSeq(7) },
            payload,
        },
    );
    assert_encoded_len("SessionFrame::Ping", &SessionFrame::<Vec<u8>>::Ping);
    assert_encoded_len(
        "SessionFrame::Close",
        &SessionFrame::<Vec<u8>>::Close(SessionClose {
            code: SessionCloseCode::PROTOCOL,
        }),
    );
    assert_encoded_len(
        "Xx1",
        &Xx1 {
            handshake_id: handshake_id(1),
            pairing_id: PairingId([4u8; PairingId::SIZE]),
            transport_params: params,
            ephemeral: ephemeral_public_key(),
        },
    );
    assert_encoded_len(
        "Xx2",
        &Xx2 {
            handshake_id: handshake_id(2),
            transport_params: params,
            ekem_ciphertext: mlkem_ciphertext(),
            static_bundle: encrypted_peer_bundle(),
        },
    );
    assert_encoded_len(
        "Xx3",
        &Xx3 {
            handshake_id: handshake_id(3),
            skem_ciphertext: encrypted_mlkem_ciphertext(),
            static_bundle: encrypted_peer_bundle(),
        },
    );
    assert_encoded_len(
        "Xx4",
        &Xx4 {
            handshake_id: handshake_id(4),
            skem_ciphertext: encrypted_mlkem_ciphertext(),
        },
    );
    assert_encoded_len(
        "Ik1",
        &Ik1 {
            handshake_id: handshake_id(5),
            transport_params: params,
            skem_ciphertext: mlkem_ciphertext(),
            ephemeral: ephemeral_public_key(),
            static_bundle: Some(encrypted_peer_bundle()),
        },
    );
    assert_encoded_len(
        "Ik1 without bundle",
        &Ik1 {
            handshake_id: handshake_id(5),
            transport_params: params,
            skem_ciphertext: mlkem_ciphertext(),
            ephemeral: ephemeral_public_key(),
            static_bundle: None,
        },
    );
    assert_encoded_len(
        "Ik2",
        &Ik2 {
            handshake_id: handshake_id(6),
            transport_params: params,
            ekem_ciphertext: mlkem_ciphertext(),
            skem_ciphertext: encrypted_mlkem_ciphertext(),
        },
    );
}
