use std::sync::atomic::{AtomicU8, Ordering};

use libcrux_aesgcm::AesGcm256Key;
use sha2::{Digest, Sha256};

use super::*;

struct TestCrypto(AtomicU8);

impl TestCrypto {
    fn new(seed: u8) -> Self {
        Self(AtomicU8::new(seed))
    }
}

impl QlCrypto for TestCrypto {
    fn fill_random_bytes(&self, data: &mut [u8]) {
        let seed = self.0.fetch_add(1, Ordering::Relaxed);
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = seed.wrapping_add(index as u8);
        }
    }

    fn hash(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().into()
    }

    fn encrypt_with_aead(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> [u8; EncryptedMessage::AUTH_SIZE] {
        let key: AesGcm256Key = (*key.data()).into();
        let plaintext = buffer.to_vec();
        let mut auth = [0u8; EncryptedMessage::AUTH_SIZE];
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

    fn decrypt_with_aead(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
        auth_tag: &[u8; EncryptedMessage::AUTH_SIZE],
    ) -> bool {
        let key: AesGcm256Key = (*key.data()).into();
        let ciphertext = buffer.to_vec();
        key.decrypt(buffer, (&nonce.0).into(), aad, &ciphertext, auth_tag.into())
            .is_ok()
    }
}

#[test]
fn encrypted_session_record_round_trip_and_decrypt() {
    let crypto = TestCrypto::new(1);
    let header = QlHeader {
        sender: XID([1; XID::SIZE]),
        recipient: XID([2; XID::SIZE]),
    };
    let body = SessionEnvelope {
        seq: SessionSeq(7),
        ack: SessionAck {
            base: SessionSeq(3),
            bitmap: 0b101,
        },
        body: SessionBody::Stream(StreamChunk {
            stream_id: StreamId(9),
            chunk_seq: 11,
            bytes: b"hello".to_vec(),
            fin: true,
        }),
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
    assert_eq!(decoded.header, header);
    assert!(matches!(decoded.payload, QlPayload::Session(_)));

    let parsed = QlRecord::parse(&bytes).unwrap();
    assert_eq!(parsed.to_owned(), record);

    let mut bytes = bytes;
    let QlRecordRef { header, payload } = QlRecord::parse_mut(&mut bytes).unwrap();
    let QlPayloadRef::Session(mut encrypted) = payload else {
        panic!("expected session payload");
    };
    let decrypted =
        encrypted::decrypt_record(&crypto, &header, &mut encrypted, &session_key).unwrap();
    assert_eq!(SessionEnvelope::from_wire(&decrypted).unwrap(), body);
}

#[test]
fn pair_request_round_trip_and_decrypt() {
    let crypto = TestCrypto::new(9);
    let sender_signing = generate_ml_dsa_keypair(&crypto);
    let sender_kem = generate_ml_kem_keypair(&crypto);
    let recipient_signing = generate_ml_dsa_keypair(&crypto);
    let recipient_kem = generate_ml_kem_keypair(&crypto);

    let sender = QlIdentity::new(
        XID([3; XID::SIZE]),
        sender_signing.0,
        sender_signing.1,
        sender_kem.0,
        sender_kem.1,
    );
    let recipient = QlIdentity::new(
        XID([4; XID::SIZE]),
        recipient_signing.0,
        recipient_signing.1,
        recipient_kem.0,
        recipient_kem.1,
    );
    let meta = ControlMeta {
        control_id: ControlId(55),
        valid_until: 999,
    };
    let record = pair::build_pair_request(
        &crypto,
        &sender,
        recipient.xid,
        &recipient.encapsulation_public_key,
        meta,
    );

    let mut bytes = record.encode();
    let QlRecordRef { header, payload } = QlRecord::parse_mut(&mut bytes).unwrap();
    let QlPayloadRef::PairRequest(mut request) = payload else {
        panic!("expected pair request");
    };
    let body = pair::decrypt_pair_request(&crypto, &recipient, &header, &mut request, 100).unwrap();
    assert_eq!(body.meta, meta);
    assert_eq!(body.xid, sender.xid);
    assert_eq!(body.signing_pub_key, sender.signing_public_key);
    assert_eq!(body.encapsulation_pub_key, sender.encapsulation_public_key);
}

#[test]
fn ready_round_trip_and_decrypt() {
    let crypto = TestCrypto::new(30);
    let header = QlHeader {
        sender: XID([5; XID::SIZE]),
        recipient: XID([6; XID::SIZE]),
    };
    let session_key = SessionKey::from_data([11; SessionKey::SIZE]);
    let meta = ControlMeta {
        control_id: ControlId(77),
        valid_until: 500,
    };
    let ready = handshake::build_ready(
        &crypto,
        header,
        &session_key,
        meta,
        Nonce([12; Nonce::SIZE]),
    );
    let record = QlRecord {
        header,
        payload: QlPayload::Ready(ready),
    };

    let mut bytes = record.encode();
    let parsed = QlRecord::decode(&bytes).unwrap();
    assert_eq!(parsed, record);

    let QlRecordRef { header, payload } = QlRecord::parse_mut(&mut bytes).unwrap();
    let QlPayloadRef::Ready(mut ready) = payload else {
        panic!("expected ready payload");
    };
    let body = handshake::decrypt_ready(&crypto, &header, &mut ready, &session_key, 100).unwrap();
    assert_eq!(body.meta, meta);
}

#[test]
fn unpair_round_trip_and_verify() {
    let crypto = TestCrypto::new(40);
    let (sender_signing_private, sender_signing_public) = generate_ml_dsa_keypair(&crypto);
    let sender_kem = generate_ml_kem_keypair(&crypto);
    let identity = QlIdentity::new(
        XID([7; XID::SIZE]),
        sender_signing_private,
        sender_signing_public.clone(),
        sender_kem.0,
        sender_kem.1,
    );
    let recipient = XID([8; XID::SIZE]);
    let meta = ControlMeta {
        control_id: ControlId(88),
        valid_until: 600,
    };
    let record = unpair::build_unpair(&crypto, &identity, recipient, meta);

    let mut bytes = record.encode();
    let parsed = QlRecord::decode(&bytes).unwrap();
    assert_eq!(parsed, record);

    let QlRecordRef { header, payload } = QlRecord::parse_mut(&mut bytes).unwrap();
    let QlPayloadRef::Unpair(unpair) = payload else {
        panic!("expected unpair payload");
    };
    unpair::verify_unpair(
        &crypto,
        &header,
        &sender_signing_public,
        &unpair,
        100,
    )
    .unwrap();
}

#[test]
fn protocol_record_size_breakdown() {
    fn meta(id: u32) -> ControlMeta {
        ControlMeta {
            control_id: ControlId(id),
            valid_until: 1_000,
        }
    }

    fn header() -> QlHeader {
        QlHeader {
            sender: XID([1; XID::SIZE]),
            recipient: XID([2; XID::SIZE]),
        }
    }

    fn encrypted(tag: u8, ciphertext_len: usize) -> EncryptedMessage {
        EncryptedMessage {
            nonce: Nonce([tag; Nonce::SIZE]),
            auth: [tag; EncryptedMessage::AUTH_SIZE],
            ciphertext: vec![tag; ciphertext_len],
        }
    }

    fn session_record(header: QlHeader, tag: u8, body: SessionEnvelope) -> QlRecord {
        let ciphertext_len = body.encode().len();
        QlRecord {
            header,
            payload: QlPayload::Session(encrypted(tag, ciphertext_len)),
        }
    }

    let header = header();
    let hello = QlRecord {
        header,
        payload: QlPayload::Hello(handshake::Hello {
            meta: meta(1),
            nonce: Nonce([3; Nonce::SIZE]),
            kem_ct: MlKemCiphertext::from_data([4; MlKemCiphertext::SIZE]),
            signature: MlDsaSignature::from_data([5; MlDsaSignature::SIZE]),
        }),
    };
    let hello_reply = QlRecord {
        header,
        payload: QlPayload::HelloReply(handshake::HelloReply {
            meta: meta(2),
            nonce: Nonce([6; Nonce::SIZE]),
            kem_ct: MlKemCiphertext::from_data([7; MlKemCiphertext::SIZE]),
            signature: MlDsaSignature::from_data([8; MlDsaSignature::SIZE]),
        }),
    };
    let confirm = QlRecord {
        header,
        payload: QlPayload::Confirm(handshake::Confirm {
            meta: meta(3),
            signature: MlDsaSignature::from_data([9; MlDsaSignature::SIZE]),
        }),
    };
    let pair_request = QlRecord {
        header,
        payload: QlPayload::PairRequest(pair::PairRequestRecord {
            kem_ct: MlKemCiphertext::from_data([10; MlKemCiphertext::SIZE]),
            encrypted: encrypted(11, 0),
        }),
    };
    let unpair = QlRecord {
        header,
        payload: QlPayload::Unpair(unpair::Unpair {
            meta: meta(4),
            signature: MlDsaSignature::from_data([12; MlDsaSignature::SIZE]),
        }),
    };
    let ready = QlRecord {
        header,
        payload: QlPayload::Ready(handshake::Ready {
            encrypted: encrypted(13, 0),
        }),
    };

    let session_ack = session_record(
        header,
        14,
        SessionEnvelope {
            seq: SessionSeq(1),
            ack: SessionAck::EMPTY,
            body: SessionBody::Ack,
        },
    );
    let session_ping = session_record(
        header,
        15,
        SessionEnvelope {
            seq: SessionSeq(2),
            ack: SessionAck::EMPTY,
            body: SessionBody::Ping(PingBody),
        },
    );
    let session_stream_empty = session_record(
        header,
        16,
        SessionEnvelope {
            seq: SessionSeq(3),
            ack: SessionAck::EMPTY,
            body: SessionBody::Stream(StreamChunk {
                stream_id: StreamId(1),
                chunk_seq: 0,
                fin: false,
                bytes: Vec::new(),
            }),
        },
    );
    let session_stream_fin = session_record(
        header,
        17,
        SessionEnvelope {
            seq: SessionSeq(4),
            ack: SessionAck::EMPTY,
            body: SessionBody::Stream(StreamChunk {
                stream_id: StreamId(1),
                chunk_seq: 0,
                fin: true,
                bytes: Vec::new(),
            }),
        },
    );
    let session_stream_close = session_record(
        header,
        18,
        SessionEnvelope {
            seq: SessionSeq(5),
            ack: SessionAck::EMPTY,
            body: SessionBody::StreamClose(StreamClose {
                stream_id: StreamId(1),
                target: CloseTarget::Both,
                code: CloseCode::PROTOCOL,
                payload: Vec::new(),
            }),
        },
    );
    let session_close = session_record(
        header,
        19,
        SessionEnvelope {
            seq: SessionSeq(6),
            ack: SessionAck::EMPTY,
            body: SessionBody::Close(SessionCloseBody {
                code: CloseCode::PROTOCOL,
            }),
        },
    );

    let print_size = |label: &str, size: usize| {
        println!("{label:<32}: {size} bytes");
    };

    print_size("ql-wire hello", hello.encode().len());
    print_size("ql-wire hello_reply", hello_reply.encode().len());
    print_size("ql-wire confirm", confirm.encode().len());
    print_size("ql-wire pair_request empty", pair_request.encode().len());
    print_size("ql-wire unpair", unpair.encode().len());
    print_size("ql-wire ready empty", ready.encode().len());
    print_size("ql-wire session ack", session_ack.encode().len());
    print_size("ql-wire session ping", session_ping.encode().len());
    print_size(
        "ql-wire session stream empty",
        session_stream_empty.encode().len(),
    );
    print_size(
        "ql-wire session stream fin",
        session_stream_fin.encode().len(),
    );
    print_size(
        "ql-wire session stream close",
        session_stream_close.encode().len(),
    );
    print_size("ql-wire session close", session_close.encode().len());
}
