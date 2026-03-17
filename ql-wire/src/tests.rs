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
    ) -> Option<[u8; AUTH_SIZE]> {
        let key: AesGcm256Key = (*key.data()).into();
        let plaintext = buffer.to_vec();
        let mut auth = [0u8; AUTH_SIZE];
        key.encrypt(
            buffer,
            (&mut auth).into(),
            (&nonce.0).into(),
            aad,
            &plaintext,
        )
        .ok()?;
        Some(auth)
    }

    fn decrypt_with_aead(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
        auth_tag: &[u8; AUTH_SIZE],
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
        sender: XID([1; XID_SIZE]),
        recipient: XID([2; XID_SIZE]),
    };
    let body = SessionEnvelope {
        seq: SessionSeq(7),
        ack: SessionAck {
            base: SessionSeq(3),
            bitmap: 0b101,
        },
        body: SessionBody::Stream(StreamChunk {
            stream_id: StreamId(9),
            offset: 11,
            bytes: b"hello".to_vec(),
            fin: true,
        }),
    };
    let session_key = SessionKey::from_data([7; SessionKey::SIZE]);
    let record =
        encrypted::encrypt_record(&crypto, header, &session_key, &body, Nonce([8; NONCE_SIZE]))
            .unwrap();

    let bytes = record.encode();
    let decoded = QlRecord::decode(&bytes).unwrap();
    assert_eq!(decoded.header, header);
    assert!(matches!(decoded.payload, QlPayload::Session(_)));

    let parsed = QlRecord::parse(&bytes).unwrap();
    assert_eq!(parsed.to_owned(), record);

    let mut bytes = bytes;
    let QlRecordMut { header, payload } = QlRecord::parse_mut(&mut bytes).unwrap();
    let QlPayloadMut::Session(mut encrypted) = payload else {
        panic!("expected session payload");
    };
    let decrypted =
        encrypted::decrypt_record(&crypto, &header, &mut encrypted, &session_key).unwrap();
    assert_eq!(decrypted.to_session_envelope().unwrap(), body);
}

#[test]
fn pair_request_round_trip_and_decrypt() {
    let crypto = TestCrypto::new(9);
    let sender_signing = generate_ml_dsa_keypair(&crypto);
    let sender_kem = generate_ml_kem_keypair(&crypto);
    let recipient_signing = generate_ml_dsa_keypair(&crypto);
    let recipient_kem = generate_ml_kem_keypair(&crypto);

    let sender = QlIdentity::new(
        XID([3; XID_SIZE]),
        sender_signing.0,
        sender_signing.1,
        sender_kem.0,
        sender_kem.1,
    );
    let recipient = QlIdentity::new(
        XID([4; XID_SIZE]),
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
    )
    .unwrap();

    let mut bytes = record.encode();
    let QlRecordMut { header, payload } = QlRecord::parse_mut(&mut bytes).unwrap();
    let QlPayloadMut::PairRequest(mut request) = payload else {
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
        sender: XID([5; XID_SIZE]),
        recipient: XID([6; XID_SIZE]),
    };
    let session_key = SessionKey::from_data([11; SessionKey::SIZE]);
    let meta = ControlMeta {
        control_id: ControlId(77),
        valid_until: 500,
    };
    let ready =
        handshake::build_ready(&crypto, header, &session_key, meta, Nonce([12; NONCE_SIZE]))
            .unwrap();
    let record = QlRecord {
        header,
        payload: QlPayload::Ready(ready),
    };

    let mut bytes = record.encode();
    let parsed = QlRecord::decode(&bytes).unwrap();
    assert_eq!(parsed, record);

    let QlRecordMut { header, payload } = QlRecord::parse_mut(&mut bytes).unwrap();
    let QlPayloadMut::Ready(mut ready) = payload else {
        panic!("expected ready payload");
    };
    let body = handshake::decrypt_ready(&crypto, &header, &mut ready, &session_key, 100).unwrap();
    assert_eq!(body.meta, meta);
}
