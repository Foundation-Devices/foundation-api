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
    let body = SessionRecord {
        frames: vec![
            SessionFrame::Ping,
            SessionFrame::Pong,
            SessionFrame::StreamAck(StreamAck {
                stream_id: StreamId(7),
                acked_prefix: 12,
                ranges: vec![
                    StreamAckRange {
                        start_offset: 20,
                        end_offset: 24,
                    },
                    StreamAckRange {
                        start_offset: 30,
                        end_offset: 33,
                    },
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
                payload: b"bye".to_vec(),
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
    assert_eq!(SessionRecord::from_wire(&decrypted).unwrap(), body);
}

#[test]
fn decrypted_session_record_iterates_zero_copy_frames() {
    let crypto = TestCrypto::new(2);
    let header = QlHeader {
        sender: XID([9; XID::SIZE]),
        recipient: XID([10; XID::SIZE]),
    };
    let body = SessionRecord {
        frames: vec![
            SessionFrame::StreamData(StreamData {
                stream_id: StreamId(1),
                offset: 5,
                fin: false,
                bytes: b"abc".to_vec(),
            }),
            SessionFrame::StreamAck(StreamAck {
                stream_id: StreamId(1),
                acked_prefix: 3,
                ranges: vec![StreamAckRange {
                    start_offset: 5,
                    end_offset: 8,
                }],
            }),
            SessionFrame::StreamClose(StreamClose {
                stream_id: StreamId(1),
                target: CloseTarget::Response,
                code: CloseCode::CANCELLED,
                payload: b"later".to_vec(),
            }),
        ],
    };
    let session_key = SessionKey::from_data([3; SessionKey::SIZE]);
    let record = encrypted::encrypt_record(
        &crypto,
        header,
        &session_key,
        &body,
        Nonce([4; Nonce::SIZE]),
    );

    let mut bytes = record.encode();
    let QlRecordRef { header, payload } = QlRecord::parse_mut(&mut bytes).unwrap();
    let QlPayloadRef::Session(mut encrypted) = payload else {
        panic!("expected session payload");
    };
    let decrypted =
        encrypted::decrypt_record(&crypto, &header, &mut encrypted, &session_key).unwrap();

    let mut frames = decrypted.frames();
    match frames.next().unwrap().unwrap() {
        SessionFrameRef::StreamData(frame) => {
            assert_eq!(frame.stream_id(), StreamId(1));
            assert_eq!(frame.offset(), 5);
            assert!(!frame.fin().unwrap());
            assert_eq!(frame.bytes(), b"abc");
        }
        other => panic!("expected stream data, got {}", frame_name(&other)),
    }
    match frames.next().unwrap().unwrap() {
        SessionFrameRef::StreamAck(frame) => {
            assert_eq!(frame.stream_id(), StreamId(1));
            assert_eq!(frame.acked_prefix(), 3);
            let ranges: Vec<_> = frame.ranges().collect();
            assert_eq!(
                ranges,
                vec![StreamAckRange {
                    start_offset: 5,
                    end_offset: 8,
                }]
            );
        }
        other => panic!("expected stream ack, got {}", frame_name(&other)),
    }
    match frames.next().unwrap().unwrap() {
        SessionFrameRef::StreamClose(frame) => {
            let owned = StreamClose::from_wire(&frame).unwrap();
            assert_eq!(owned.stream_id, StreamId(1));
            assert_eq!(owned.target, CloseTarget::Response);
            assert_eq!(owned.payload, b"later".to_vec());
        }
        other => panic!("expected stream close, got {}", frame_name(&other)),
    }
    assert!(frames.next().is_none());
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
    unpair::verify_unpair(&crypto, &header, &sender_signing_public, &unpair, 100).unwrap();
}

#[test]
fn session_record_rejects_malformed_frames() {
    let invalid_cases = [
        vec![0xff],
        {
            let mut bytes = vec![SessionFrameKind::StreamData as u8];
            bytes.push(1);
            bytes
        },
        {
            let mut bytes = vec![SessionFrameKind::StreamData as u8];
            bytes.extend_from_slice(&13u16.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&4u64.to_le_bytes());
            bytes.push(0);
            bytes.extend_from_slice(b"abc");
            bytes
        },
        {
            let mut bytes = vec![SessionFrameKind::StreamAck as u8];
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&3u64.to_le_bytes());
            bytes.extend_from_slice(&5u64.to_le_bytes());
            bytes
        },
        {
            let mut bytes = vec![SessionFrameKind::StreamAck as u8];
            bytes.extend_from_slice(&28u16.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&6u64.to_le_bytes());
            bytes.extend_from_slice(&4u64.to_le_bytes());
            bytes.extend_from_slice(&8u64.to_le_bytes());
            bytes
        },
        {
            let mut bytes = vec![SessionFrameKind::StreamClose as u8];
            bytes.extend_from_slice(&9u16.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.push(CloseTarget::Both as u8);
            bytes.extend_from_slice(&CloseCode::PROTOCOL.0.to_le_bytes());
            bytes.extend_from_slice(b"abc");
            bytes
        },
        {
            let mut bytes = vec![SessionFrameKind::Close as u8];
            bytes.push(0);
            bytes
        },
    ];

    for bytes in invalid_cases {
        assert_eq!(SessionRecord::decode(&bytes), Err(WireError::InvalidPayload));
    }
}

#[test]
fn session_record_supports_empty_fin_stream_data_and_empty_ping_pong() {
    let record = SessionRecord {
        frames: vec![
            SessionFrame::Ping,
            SessionFrame::Pong,
            SessionFrame::StreamData(StreamData {
                stream_id: StreamId(42),
                offset: 999,
                fin: true,
                bytes: Vec::new(),
            }),
        ],
    };

    let encoded = record.encode();
    assert_eq!(encoded[0], SessionFrameKind::Ping as u8);
    assert_eq!(encoded[1], SessionFrameKind::Pong as u8);

    let decoded = SessionRecord::decode(&encoded).unwrap();
    assert_eq!(decoded, record);
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

    fn session_record(header: QlHeader, tag: u8, body: SessionRecord) -> QlRecord {
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

    let session_ping = session_record(
        header,
        14,
        SessionRecord {
            frames: vec![SessionFrame::Ping],
        },
    );
    let session_pong = session_record(
        header,
        15,
        SessionRecord {
            frames: vec![SessionFrame::Pong],
        },
    );
    let session_stream_window = session_record(
        header,
        16,
        SessionRecord {
            frames: vec![SessionFrame::StreamWindow(StreamWindow {
                stream_id: StreamId(1),
                maximum_offset: 65_536,
            })],
        },
    );
    let session_stream_ack = session_record(
        header,
        17,
        SessionRecord {
            frames: vec![SessionFrame::StreamAck(StreamAck {
                stream_id: StreamId(1),
                acked_prefix: 4,
                ranges: vec![StreamAckRange {
                    start_offset: 8,
                    end_offset: 12,
                }],
            })],
        },
    );
    let session_stream_empty = session_record(
        header,
        18,
        SessionRecord {
            frames: vec![SessionFrame::StreamData(StreamData {
                stream_id: StreamId(1),
                offset: 0,
                fin: false,
                bytes: Vec::new(),
            })],
        },
    );
    let session_stream_fin = session_record(
        header,
        19,
        SessionRecord {
            frames: vec![SessionFrame::StreamData(StreamData {
                stream_id: StreamId(1),
                offset: 0,
                fin: true,
                bytes: Vec::new(),
            })],
        },
    );
    let session_stream_close = session_record(
        header,
        20,
        SessionRecord {
            frames: vec![SessionFrame::StreamClose(StreamClose {
                stream_id: StreamId(1),
                target: CloseTarget::Both,
                code: CloseCode::PROTOCOL,
                payload: Vec::new(),
            })],
        },
    );
    let session_close = session_record(
        header,
        21,
        SessionRecord {
            frames: vec![SessionFrame::Close(SessionCloseBody {
                code: CloseCode::PROTOCOL,
            })],
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
    print_size("ql-wire session ping", session_ping.encode().len());
    print_size("ql-wire session pong", session_pong.encode().len());
    print_size("ql-wire session stream window", session_stream_window.encode().len());
    print_size("ql-wire session stream ack", session_stream_ack.encode().len());
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

fn frame_name(frame: &SessionFrameRef<'_>) -> &'static str {
    match frame {
        SessionFrameRef::Ping => "ping",
        SessionFrameRef::Pong => "pong",
        SessionFrameRef::StreamData(_) => "stream_data",
        SessionFrameRef::StreamAck(_) => "stream_ack",
        SessionFrameRef::StreamWindow(_) => "stream_window",
        SessionFrameRef::StreamClose(_) => "stream_close",
        SessionFrameRef::Close(_) => "close",
    }
}
