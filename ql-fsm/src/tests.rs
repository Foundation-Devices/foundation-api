use std::{
    cell::Cell,
    time::{Duration, Instant},
};

use bc_components::{MLDSA, MLKEM, SymmetricKey};
use rkyv::api::low;
use ql_wire::{self, QlCrypto, QlIdentity, QlPayload, QlRecord};

use crate::{
    session::{SessionFsm, SessionFsmConfig, StreamNamespace},
    FsmTime, Peer, PeerSession, QlFsm, QlFsmConfig, QlSessionEvent, RecentReady,
};

#[derive(Clone)]
struct TestCrypto {
    seed: u8,
    counter: Cell<u8>,
}

impl TestCrypto {
    fn new(seed: u8) -> Self {
        Self {
            seed,
            counter: Cell::new(0),
        }
    }
}

impl QlCrypto for TestCrypto {
    fn fill_random_bytes(&self, data: &mut [u8]) {
        let value = self.seed.wrapping_add(self.counter.get());
        self.counter.set(self.counter.get().wrapping_add(1));
        data.fill(value);
    }
}

struct Node {
    fsm: QlFsm,
    crypto: TestCrypto,
}

struct Harness {
    now: Instant,
    unix_secs: u64,
    a: Node,
    b: Node,
}

impl Harness {
    fn connected(config: QlFsmConfig) -> Self {
        let identity_a = test_identity();
        let identity_b = test_identity();
        let peer_a = peer_from_identity(&identity_b);
        let peer_b = peer_from_identity(&identity_a);
        let session_key = SymmetricKey::from_data([7; SymmetricKey::SYMMETRIC_KEY_SIZE]);
        let now = Instant::now();
        let time = FsmTime {
            instant: now,
            unix_secs: 1_000,
        };
        let mut harness = Self {
            now,
            unix_secs: time.unix_secs,
            a: Node {
                fsm: QlFsm::new(
                    config,
                    identity_a.clone(),
                    Some(peer_a),
                    time,
                ),
                crypto: TestCrypto::new(1),
            },
            b: Node {
                fsm: QlFsm::new(
                    config,
                    identity_b.clone(),
                    Some(peer_b),
                    time,
                ),
                crypto: TestCrypto::new(2),
            },
        };
        harness.a.fsm.peer.as_mut().unwrap().session = PeerSession::Connected {
            session_key: session_key.clone(),
            recent_ready: None::<RecentReady>,
        };
        harness.b.fsm.peer.as_mut().unwrap().session = PeerSession::Connected {
            session_key,
            recent_ready: None::<RecentReady>,
        };
        harness.a.fsm.session = SessionFsm::new(
            SessionFsmConfig {
                local_namespace: StreamNamespace::for_local(
                    harness.a.fsm.identity.xid,
                    harness.a.fsm.peer.as_ref().unwrap().peer.xid,
                ),
                ack_delay: config.session_ack_delay,
                retransmit_timeout: config.session_retransmit_timeout,
            },
            now,
        );
        harness.b.fsm.session = SessionFsm::new(
            SessionFsmConfig {
                local_namespace: StreamNamespace::for_local(
                    harness.b.fsm.identity.xid,
                    harness.b.fsm.peer.as_ref().unwrap().peer.xid,
                ),
                ack_delay: config.session_ack_delay,
                retransmit_timeout: config.session_retransmit_timeout,
            },
            now,
        );
        harness
    }

    fn time(&self) -> FsmTime {
        FsmTime {
            instant: self.now,
            unix_secs: self.unix_secs,
        }
    }

    fn advance(&mut self, duration: Duration) {
        self.now += duration;
        self.unix_secs = self.unix_secs.saturating_add(duration.as_secs());
    }

    fn pump(&mut self) {
        for _ in 0..128 {
            let progressed_a = self.flush_a_to_b();
            let progressed_b = self.flush_b_to_a();
            let progressed = progressed_a || progressed_b;
            if !progressed {
                return;
            }
        }
        panic!("pump did not quiesce");
    }

    fn flush_a_to_b(&mut self) -> bool {
        let mut progressed = false;
        while let Some(record) = self.a.fsm.take_next_outbound(self.time(), &self.a.crypto) {
            progressed = true;
            let bytes = ql_wire::encode_record(&record);
            self.b
                .fsm
                .receive(self.time(), bytes, &self.b.crypto)
                .unwrap();
        }
        progressed
    }

    fn flush_b_to_a(&mut self) -> bool {
        let mut progressed = false;
        while let Some(record) = self.b.fsm.take_next_outbound(self.time(), &self.b.crypto) {
            progressed = true;
            let bytes = ql_wire::encode_record(&record);
            self.a
                .fsm
                .receive(self.time(), bytes, &self.a.crypto)
                .unwrap();
        }
        progressed
    }
}

#[test]
fn connected_fsms_deliver_stream_data() {
    let mut harness = Harness::connected(QlFsmConfig::default());

    let stream_id = harness.a.fsm.open_stream().unwrap();
    harness
        .a
        .fsm
        .write_stream(stream_id, b"hello".to_vec())
        .unwrap();
    harness.a.fsm.finish_stream(stream_id).unwrap();

    harness.pump();

    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Opened(stream_id))
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Data {
            stream_id,
            bytes: b"hello".to_vec(),
        })
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Finished(stream_id))
    );
}

#[test]
fn lost_encrypted_record_is_retried_and_acked() {
    let config = QlFsmConfig::default();
    let mut harness = Harness::connected(config);

    let stream_id = harness.a.fsm.open_stream().unwrap();
    harness
        .a
        .fsm
        .write_stream(stream_id, b"retry".to_vec())
        .unwrap();

    let first = harness
        .a
        .fsm
        .take_next_outbound(harness.time(), &harness.a.crypto)
        .unwrap();
    let session_key = harness
        .b
        .fsm
        .peer
        .as_ref()
        .unwrap()
        .session
        .session_key()
        .unwrap()
        .clone();
    let first_body = decrypt_envelope(&first, &session_key);

    harness.advance(config.session_retransmit_timeout + Duration::from_millis(1));

    let retried = harness
        .a
        .fsm
        .take_next_outbound(harness.time(), &harness.a.crypto)
        .unwrap();
    let retried_body = decrypt_envelope(&retried, &session_key);

    assert_ne!(first_body.seq, retried_body.seq);
    assert_eq!(first_body.body, retried_body.body);

    harness
        .b
        .fsm
        .receive(harness.time(), ql_wire::encode_record(&retried), &harness.b.crypto)
        .unwrap();
    harness.pump();

    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Opened(stream_id))
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Data {
            stream_id,
            bytes: b"retry".to_vec(),
        })
    );

    harness.advance(config.session_retransmit_timeout + Duration::from_millis(1));
    assert!(harness
        .a
        .fsm
        .take_next_outbound(harness.time(), &harness.a.crypto)
        .is_none());
}

#[test]
fn remote_unpair_clears_peer() {
    let mut harness = Harness::connected(QlFsmConfig::default());

    harness.a.fsm.queue_unpair().unwrap();
    harness.pump();

    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Unpaired)
    );
    assert!(harness.b.fsm.peer.is_none());
    assert!(matches!(
        harness.b.fsm.take_next_event(),
        Some(crate::QlFsmEvent::ClearPeer)
    ));
    assert!(harness.a.fsm.peer.is_some());
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
        xid: identity.xid,
        signing_key: identity.signing_public_key.clone(),
        encapsulation_key: identity.encapsulation_public_key.clone(),
    }
}

fn decrypt_envelope(record: &QlRecord, session_key: &SymmetricKey) -> ql_wire::SessionEnvelope {
    let record = record.clone();
    let aad = record.header.aad();
    let QlPayload::Encrypted(encrypted) = record.payload else {
        panic!("expected encrypted payload");
    };
    let plaintext = encrypted.decrypt(session_key, &aad).unwrap();
    let archived = rkyv::access::<ql_wire::encrypted::ArchivedSessionEnvelope, rkyv::rancor::Error>(
        &plaintext,
    )
    .unwrap();
    low::deserialize::<ql_wire::SessionEnvelope, rkyv::rancor::Error>(archived).unwrap()
}
