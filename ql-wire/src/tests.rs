use std::sync::atomic::{AtomicU64, Ordering};

use libcrux_aesgcm::AesGcm256Key;
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
        let seed = self.next_block();
        let key_id = self.sha256(&[b"ql-wire:test-mlkem:key-id:v1", &seed]);

        let mut public = [0u8; MlKemPublicKey::SIZE];
        fill_expanded(self, &[b"ql-wire:test-mlkem:public:v1", &seed], &mut public);
        public[..key_id.len()].copy_from_slice(&key_id);

        let mut private = [0u8; MlKemPrivateKey::SIZE];
        fill_expanded(
            self,
            &[b"ql-wire:test-mlkem:private:v1", &seed],
            &mut private,
        );
        private[..key_id.len()].copy_from_slice(&key_id);

        MlKemKeyPair {
            private: MlKemPrivateKey::from_data(private),
            public: MlKemPublicKey::from_data(public),
        }
    }

    fn mlkem_encapsulate(&self, public_key: &MlKemPublicKey) -> (MlKemCiphertext, SessionKey) {
        let mut encaps_seed = [0u8; 32];
        self.fill_random_bytes(&mut encaps_seed);
        let key_id = &public_key.as_bytes()[..32];

        let mut ciphertext = [0u8; MlKemCiphertext::SIZE];
        fill_expanded(
            self,
            &[b"ql-wire:test-mlkem:ciphertext:v1", &encaps_seed],
            &mut ciphertext,
        );
        ciphertext[..encaps_seed.len()].copy_from_slice(&encaps_seed);

        let shared = self.sha256(&[b"ql-wire:test-mlkem:shared:v1", key_id, &encaps_seed]);
        (
            MlKemCiphertext::from_data(ciphertext),
            SessionKey::from_data(shared),
        )
    }

    fn mlkem_decapsulate(
        &self,
        private_key: &MlKemPrivateKey,
        ciphertext: &MlKemCiphertext,
    ) -> SessionKey {
        let key_id = &private_key.as_bytes()[..32];
        let encaps_seed = &ciphertext.as_bytes()[..32];
        SessionKey::from_data(self.sha256(&[b"ql-wire:test-mlkem:shared:v1", key_id, encaps_seed]))
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

fn control_meta(id: u32) -> ControlMeta {
    ControlMeta {
        control_id: ControlId(id),
        valid_until: 10_000 + u64::from(id),
    }
}

fn make_identity(crypto: &impl QlCrypto, byte: u8) -> QlIdentity {
    generate_identity(crypto, xid(byte))
}

#[test]
fn peer_bundle_round_trip() {
    let crypto = TestCrypto::new(1);
    let identity = make_identity(&crypto, 7).with_capabilities(0x55aa_33cc);
    let bundle = identity.bundle();

    let encoded = bundle.encode();
    let decoded = PeerBundle::decode(&encoded).unwrap();

    assert_eq!(decoded, bundle);
}

#[test]
fn handshake_record_round_trip_uses_handshake_header() {
    let message = Xx1 {
        meta: control_meta(1),
        ephemeral: EphemeralPublicKey {
            mlkem_public_key: MlKemPublicKey::from_data([9; MlKemPublicKey::SIZE]),
        },
    };
    let record = QlHandshakeRecord {
        header: HandshakeHeader {
            sender: xid(1),
            recipient: xid(2),
        },
        payload: HandshakePayload::Xx1(message),
    };

    let encoded = record.encode();
    let decoded = QlHandshakeRecord::decode(&encoded).unwrap();

    assert_eq!(decoded, record);

    let decoded = QlRecord::decode(&encoded).unwrap();
    assert_eq!(decoded, QlRecord::Handshake(record));
}

#[test]
fn xx_handshake_round_trip_derives_matching_transport() {
    let crypto = TestCrypto::new(10);
    let initiator = make_identity(&crypto, 1);
    let responder = make_identity(&crypto, 2);

    let mut initiator_state = XxHandshake::new_initiator(&crypto, initiator.clone());
    let mut responder_state = XxHandshake::new_responder(&crypto, responder.clone());

    let m1 = initiator_state
        .write_message(&crypto, control_meta(1))
        .unwrap();
    responder_state.read_message(&crypto, &m1).unwrap();

    let m2 = responder_state
        .write_message(&crypto, control_meta(2))
        .unwrap();
    initiator_state.read_message(&crypto, &m2).unwrap();

    let m3 = initiator_state
        .write_message(&crypto, control_meta(3))
        .unwrap();
    responder_state.read_message(&crypto, &m3).unwrap();

    let m4 = responder_state
        .write_message(&crypto, control_meta(4))
        .unwrap();
    initiator_state.read_message(&crypto, &m4).unwrap();

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
    let crypto = TestCrypto::new(20);
    let initiator = make_identity(&crypto, 3);
    let responder = make_identity(&crypto, 4);

    let mut initiator_state =
        KkHandshake::new_initiator(&crypto, initiator.clone(), responder.bundle());
    let mut responder_state =
        KkHandshake::new_responder(&crypto, responder.clone(), initiator.bundle());

    let m1 = initiator_state
        .write_message(&crypto, control_meta(11))
        .unwrap();
    responder_state.read_message(&crypto, &m1).unwrap();

    let m2 = responder_state
        .write_message(&crypto, control_meta(12))
        .unwrap();
    initiator_state.read_message(&crypto, &m2).unwrap();

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
    let crypto = TestCrypto::new(30);
    let header = SessionHeader {
        connection_id: ConnectionId::from_data([0x44; ConnectionId::SIZE]),
    };
    let body = SessionRecord {
        seq: RecordSeq(11),
        frames: vec![
            SessionFrame::Ping,
            SessionFrame::Ack(RecordAck {
                ranges: vec![
                    RecordAckRange { start: 12, end: 14 },
                    RecordAckRange { start: 20, end: 24 },
                ],
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
                code: CloseCode::PROTOCOL,
            }),
            SessionFrame::Close(SessionCloseBody {
                code: CloseCode::TIMEOUT,
            }),
        ],
    };
    let session_key = SessionKey::from_data([7; SessionKey::SIZE]);
    let record = encrypted::encrypt_record(
        &crypto,
        header,
        &session_key,
        &body,
        Nonce([8; Nonce::SIZE]),
    );

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
    };
    assert_eq!(
        encrypted::decrypt_record(&crypto, &wrong_header, encrypted, &session_key),
        Err(WireError::DecryptFailed)
    );
}
