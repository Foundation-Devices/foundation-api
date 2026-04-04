use std::sync::atomic::{AtomicU64, Ordering};

use libcrux_aesgcm::AesGcm256Key;
use libcrux_ml_kem::mlkem1024;
use sha2::{Digest, Sha256};

use super::*;

struct TestCrypto {
    counter: AtomicU64,
}

impl TestCrypto {
    fn new(seed: u64) -> Self {
        Self {
            counter: AtomicU64::new(seed),
        }
    }

    fn next_block(&self) -> [u8; 32] {
        let value = self.counter.fetch_add(1, Ordering::Relaxed).to_le_bytes();
        sha256_parts(&[b"ql-wire:test-rng:v1", &value])
    }

    fn random_array<const L: usize>(&self) -> [u8; L] {
        let mut out = [0u8; L];
        self.fill_random_bytes(&mut out);
        out
    }
}

impl QlRandom for TestCrypto {
    fn fill_random_bytes(&self, out: &mut [u8]) {
        fill_expanded(self, &[b"ql-wire:test-fill:v1"], out);
    }
}

impl QlHash for TestCrypto {
    fn sha256(&self, parts: &[&[u8]]) -> [u8; 32] {
        sha256_parts(parts)
    }
}

impl QlAead for TestCrypto {
    fn aes256_gcm_encrypt(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> [u8; ENCRYPTED_MESSAGE_AUTH_SIZE] {
        let key: AesGcm256Key = (*key.data()).into();
        let plaintext = buffer.to_vec();
        let mut auth = [0u8; ENCRYPTED_MESSAGE_AUTH_SIZE];
        key.encrypt(
            buffer,
            (&mut auth).into(),
            (&nonce.0).into(),
            aad,
            &plaintext,
        )
        .unwrap();
        auth
    }

    fn aes256_gcm_decrypt(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
        auth_tag: &[u8; ENCRYPTED_MESSAGE_AUTH_SIZE],
    ) -> bool {
        let key: AesGcm256Key = (*key.data()).into();
        let ciphertext = buffer.to_vec();
        key.decrypt(buffer, (&nonce.0).into(), aad, &ciphertext, auth_tag.into())
            .is_ok()
    }
}

impl QlKem for TestCrypto {
    fn mlkem_generate_keypair(&self) -> MlKemKeyPair {
        let key_pair = mlkem1024::generate_key_pair(self.random_array());
        let mut public = [0u8; MlKemPublicKey::SIZE];
        public.copy_from_slice(key_pair.pk());
        let mut private = [0u8; MlKemPrivateKey::SIZE];
        private.copy_from_slice(key_pair.sk());

        MlKemKeyPair {
            private: MlKemPrivateKey::new(Box::new(private)),
            public: MlKemPublicKey::new(Box::new(public)),
        }
    }

    fn mlkem_encapsulate(&self, public_key: &MlKemPublicKey) -> (MlKemCiphertext, SessionKey) {
        let public_key = public_key.as_bytes().into();
        let (ciphertext_value, shared_value) =
            mlkem1024::encapsulate(&public_key, self.random_array());
        let mut ciphertext = [0u8; MlKemCiphertext::SIZE];
        ciphertext.copy_from_slice(ciphertext_value.as_slice());
        let mut shared = [0u8; SessionKey::SIZE];
        shared.copy_from_slice(shared_value.as_slice());
        (
            MlKemCiphertext::new(Box::new(ciphertext)),
            SessionKey::from_data(shared),
        )
    }

    fn mlkem_decapsulate(
        &self,
        private_key: &MlKemPrivateKey,
        ciphertext: &MlKemCiphertext,
    ) -> SessionKey {
        let private_key = private_key.as_bytes().into();
        let ciphertext = ciphertext.as_bytes().into();
        let shared = mlkem1024::decapsulate(&private_key, &ciphertext);
        let mut out = [0u8; SessionKey::SIZE];
        out.copy_from_slice(shared.as_slice());
        SessionKey::from_data(out)
    }
}

fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn fill_expanded(crypto: &TestCrypto, parts: &[&[u8]], out: &mut [u8]) {
    let mut written = 0usize;
    let mut counter = 0u64;
    while written < out.len() {
        let random = crypto.next_block();
        let counter_bytes = counter.to_le_bytes();
        let mut inputs = Vec::with_capacity(parts.len() + 3);
        inputs.push(b"ql-wire:test-expand:v1".as_slice());
        inputs.push(&random);
        inputs.push(&counter_bytes);
        inputs.extend_from_slice(parts);
        let block = sha256_parts(&inputs);
        let take = (out.len() - written).min(block.len());
        out[written..written + take].copy_from_slice(&block[..take]);
        written += take;
        counter = counter.wrapping_add(1);
    }
}

fn xid(byte: u8) -> XID {
    XID([byte; XID::SIZE])
}

fn handshake_meta(id: u32) -> HandshakeMeta {
    HandshakeMeta {
        handshake_id: HandshakeId(id),
        valid_until: 10_000 + u64::from(id),
    }
}

fn make_identity(crypto: &impl QlCrypto, byte: u8) -> QlIdentity {
    generate_identity(crypto, xid(byte))
}

fn handshake_header(sender: u8, recipient: u8) -> HandshakeHeader {
    HandshakeHeader {
        sender: xid(sender),
        recipient: xid(recipient),
    }
}

fn encrypt_record(
    crypto: &impl QlCrypto,
    header: SessionHeader,
    session_key: &SessionKey,
    body: &SessionRecord,
) -> QlSessionRecord<Vec<u8>> {
    let wire_size = body.wire_size() + SessionRecordBuilder::WIRE_PREFIX_LEN;
    let mut builder = SessionRecordBuilder::new(wire_size, wire_size);
    for frame in &body.frames {
        let _pushed = builder.push_frame(frame);
        debug_assert!(_pushed);
    }
    QlSessionRecord::decode(&builder.encrypt(crypto, header, session_key)).unwrap()
}

#[test]
fn peer_bundle_round_trip() {
    let crypto = TestCrypto::new(1);
    let identity = make_identity(&crypto, 7).with_capabilities(0x55aa_33cc);
    let bundle = identity.bundle();

    let encoded = bundle.encode();
    let decoded = PeerBundle::parse_bytes(encoded.as_slice()).unwrap();

    assert_eq!(decoded, bundle);
}

#[test]
fn handshake_record_round_trip_supports_ik_and_kk() {
    let ik = QlHandshakeRecord::Ik1(Ik1 {
        header: handshake_header(1, 2),
        meta: handshake_meta(1),
        skem_ciphertext: MlKemCiphertext::new(Box::new([7; MlKemCiphertext::SIZE])),
        ephemeral: EphemeralPublicKey {
            mlkem_public_key: MlKemPublicKey::new(Box::new([9; MlKemPublicKey::SIZE])),
        },
        static_bundle: EncryptedPeerBundle::new(Box::new([13; EncryptedPeerBundle::WIRE_SIZE])),
    });
    let ik_encoded = ik.encode();
    assert_eq!(QlHandshakeRecord::parse(ik_encoded.as_slice()).unwrap(), ik);
    assert_eq!(
        QlRecord::decode(&ik_encoded).unwrap(),
        QlRecord::Handshake(ik)
    );

    let kk = QlHandshakeRecord::Kk1(Kk1 {
        header: handshake_header(1, 2),
        meta: handshake_meta(2),
        skem_ciphertext: MlKemCiphertext::new(Box::new([11; MlKemCiphertext::SIZE])),
        ephemeral: EphemeralPublicKey {
            mlkem_public_key: MlKemPublicKey::new(Box::new([15; MlKemPublicKey::SIZE])),
        },
    });
    let kk_encoded = kk.encode();
    assert_eq!(QlHandshakeRecord::parse(kk_encoded.as_slice()).unwrap(), kk);
    assert_eq!(
        QlRecord::decode(&kk_encoded).unwrap(),
        QlRecord::Handshake(kk)
    );
}

#[test]
fn ik_handshake_rejects_tampered_handshake_meta() {
    let crypto = TestCrypto::new(9);
    let initiator = make_identity(&crypto, 1);
    let responder = make_identity(&crypto, 2);

    let mut initiator_state = IkHandshake::new_initiator(&crypto, initiator, responder.bundle());
    let mut responder_state = IkHandshake::new_responder(&crypto, responder, None);

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
    let crypto = TestCrypto::new(10);
    let initiator = make_identity(&crypto, 1);
    let responder = make_identity(&crypto, 2);

    let mut initiator_state =
        KkHandshake::new_initiator(&crypto, initiator.clone(), responder.bundle());
    let mut responder_state = KkHandshake::new_responder(&crypto, responder, initiator.bundle());

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
fn ik_handshake_rejects_tampered_handshake_header() {
    let crypto = TestCrypto::new(11);
    let initiator = make_identity(&crypto, 1);
    let responder = make_identity(&crypto, 2);

    let mut initiator_state = IkHandshake::new_initiator(&crypto, initiator, responder.bundle());
    let mut responder_state = IkHandshake::new_responder(&crypto, responder, None);

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
    let crypto = TestCrypto::new(12);
    let initiator = make_identity(&crypto, 1);
    let bogus = make_identity(&crypto, 1);
    let responder = make_identity(&crypto, 2);

    let mut initiator_state = IkHandshake::new_initiator(&crypto, initiator, responder.bundle());
    let mut responder_state = IkHandshake::new_responder(&crypto, responder, Some(bogus.bundle()));

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
    let crypto = TestCrypto::new(13);
    let initiator = make_identity(&crypto, 1);
    let responder = make_identity(&crypto, 2);

    let mut initiator_state = IkHandshake::new_initiator(&crypto, initiator, responder.bundle());
    let mut responder_state = IkHandshake::new_responder(&crypto, responder, None);

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
    let crypto = TestCrypto::new(20);
    let initiator = make_identity(&crypto, 3);
    let responder = make_identity(&crypto, 4);

    let mut initiator_state =
        IkHandshake::new_initiator(&crypto, initiator.clone(), responder.bundle());
    let mut responder_state = IkHandshake::new_responder(&crypto, responder.clone(), None);

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
}

#[test]
fn ik_handshake_round_trip_derives_matching_transport_with_bound_responder() {
    let crypto = TestCrypto::new(21);
    let initiator = make_identity(&crypto, 3);
    let responder = make_identity(&crypto, 4);

    let mut initiator_state =
        IkHandshake::new_initiator(&crypto, initiator.clone(), responder.bundle());
    let mut responder_state =
        IkHandshake::new_responder(&crypto, responder.clone(), Some(initiator.bundle()));

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
}

#[test]
fn kk_handshake_round_trip_derives_matching_transport() {
    let crypto = TestCrypto::new(30);
    let initiator = make_identity(&crypto, 3);
    let responder = make_identity(&crypto, 4);

    let mut initiator_state =
        KkHandshake::new_initiator(&crypto, initiator.clone(), responder.bundle());
    let mut responder_state =
        KkHandshake::new_responder(&crypto, responder.clone(), initiator.bundle());

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
}

#[test]
fn encrypted_session_record_round_trip_uses_connection_id_header() {
    let crypto = TestCrypto::new(40);
    let header = SessionHeader {
        connection_id: ConnectionId::from_data([0x44; ConnectionId::SIZE]),
        seq: RecordSeq(11),
    };
    let body = SessionRecord {
        frames: vec![
            SessionFrame::Ping,
            SessionFrame::Ack(RecordAck {
                base_seq: RecordSeq(12),
                bits: (1u64 << 0)
                    | (1u64 << 1)
                    | (1u64 << 8)
                    | (1u64 << 9)
                    | (1u64 << 10)
                    | (1u64 << 11),
            }),
            SessionFrame::StreamWindow(StreamWindow {
                stream_id: StreamId(9),
                maximum_offset: 65_536,
            }),
            SessionFrame::StreamData(StreamData {
                stream_id: StreamId(9),
                offset: 1024,
                bytes: b"hello".to_vec(),
                fin: true,
            }),
            SessionFrame::StreamClose(StreamClose {
                stream_id: StreamId(9),
                target: CloseTarget::Both,
                code: StreamCloseCode(0),
            }),
            SessionFrame::Close(SessionClose {
                code: SessionCloseCode::TIMEOUT,
            }),
        ],
    };
    let session_key = SessionKey::from_data([7; SessionKey::SIZE]);
    let record = encrypt_record(&crypto, header, &session_key, &body);

    let bytes = record.encode();
    let decoded = QlRecord::decode(&bytes).unwrap();
    let QlRecord::Session(decoded) = decoded else {
        panic!("expected session payload");
    };
    assert_eq!(decoded.header, header);
    let encrypted = decoded.payload;

    let decrypted =
        encrypted::decrypt_record(&crypto, &header, encrypted.clone(), &session_key).unwrap();
    assert_eq!(SessionRecord::decode(&decrypted).unwrap(), body);

    let decoded = QlSessionRecord::decode(&bytes).unwrap();
    assert_eq!(decoded.header, header);

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
        seq: RecordSeq(header.seq.0 + 1),
    };
    assert_eq!(
        encrypted::decrypt_record(&crypto, &wrong_seq_header, encrypted, &session_key),
        Err(WireError::DecryptFailed)
    );
}

#[test]
fn protocol_record_size_breakdown() {
    fn print_size(label: &str, size: usize) {
        println!("{label:<32}: {size} bytes");
    }

    let crypto = TestCrypto::new(50);
    let initiator = make_identity(&crypto, 1);
    let responder = make_identity(&crypto, 2);

    let mut ik_initiator =
        IkHandshake::new_initiator(&crypto, initiator.clone(), responder.bundle());
    let mut ik_responder = IkHandshake::new_responder(&crypto, responder.clone(), None);

    let ik1 = ik_initiator.write_1(&crypto, handshake_meta(101)).unwrap();
    ik_responder.read_1(&crypto, 0, &ik1).unwrap();

    let ik2 = ik_responder.write_2(&crypto, handshake_meta(101)).unwrap();
    ik_initiator.read_2(&crypto, 0, &ik2).unwrap();

    let ik1 = QlHandshakeRecord::Ik1(ik1);
    let ik2 = QlHandshakeRecord::Ik2(ik2);

    let mut kk_initiator =
        KkHandshake::new_initiator(&crypto, initiator.clone(), responder.bundle());
    let mut kk_responder = KkHandshake::new_responder(&crypto, responder, initiator.bundle());

    let kk1 = kk_initiator.write_1(&crypto, handshake_meta(201)).unwrap();
    kk_responder.read_1(&crypto, 0, &kk1).unwrap();

    let kk2 = kk_responder.write_2(&crypto, handshake_meta(201)).unwrap();
    kk_initiator.read_2(&crypto, 0, &kk2).unwrap();

    let kk1 = QlHandshakeRecord::Kk1(kk1);
    let kk2 = QlHandshakeRecord::Kk2(kk2);

    let session = ik_initiator.finalize(&crypto).unwrap();
    let session_ping = encrypt_record(
        &crypto,
        SessionHeader {
            connection_id: session.tx_connection_id,
            seq: RecordSeq(1),
        },
        &session.tx_key,
        &SessionRecord {
            frames: vec![SessionFrame::Ping],
        },
    );
    let session_stream_empty = encrypt_record(
        &crypto,
        SessionHeader {
            connection_id: session.tx_connection_id,
            seq: RecordSeq(2),
        },
        &session.tx_key,
        &SessionRecord {
            frames: vec![SessionFrame::StreamData(StreamData {
                stream_id: StreamId(1),
                offset: 0,
                fin: false,
                bytes: Vec::new(),
            })],
        },
    );
    let session_close = encrypt_record(
        &crypto,
        SessionHeader {
            connection_id: session.tx_connection_id,
            seq: RecordSeq(3),
        },
        &session.tx_key,
        &SessionRecord {
            frames: vec![SessionFrame::Close(SessionClose {
                code: SessionCloseCode::PROTOCOL,
            })],
        },
    );

    print_size("ql-wire peer bundle", initiator.bundle().encode().len());
    print_size("ql-wire mlkem public key", MlKemPublicKey::SIZE);
    print_size("ql-wire mlkem ciphertext", MlKemCiphertext::SIZE);
    print_size("ql-wire pq ik1", ik1.encode().len());
    print_size("ql-wire pq ik2", ik2.encode().len());
    print_size("ql-wire pq kk1", kk1.encode().len());
    print_size("ql-wire pq kk2", kk2.encode().len());
    print_size("ql-wire session ping", session_ping.encode().len());
    print_size(
        "ql-wire session stream empty",
        session_stream_empty.encode().len(),
    );
    print_size("ql-wire session close", session_close.encode().len());
}
