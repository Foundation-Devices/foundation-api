mod handshake;
mod session;

use std::{
    cell::Cell,
    time::{Duration, Instant},
};

use bc_components::{SymmetricKey, MLDSA, MLKEM};
use ql_wire::{self, QlCrypto, QlIdentity, QlPayload, QlRecord};
use rkyv::api::low;

use crate::{
    session::{SessionFsm, SessionFsmConfig, StreamNamespace},
    state::ConnectionState,
    FsmTime, OutboundWrite, Peer, QlFsm, QlFsmConfig, SessionWriteId,
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
    fn paired(config: QlFsmConfig) -> Self {
        let identity_a = test_identity();
        let identity_b = test_identity();
        let peer_a = peer_from_identity(&identity_b);
        let peer_b = peer_from_identity(&identity_a);
        let now = Instant::now();
        let time = FsmTime {
            instant: now,
            unix_secs: 1_700_000_000,
        };

        let mut harness = Self {
            now,
            unix_secs: time.unix_secs,
            a: Node {
                fsm: QlFsm::new(config, identity_a, time),
                crypto: TestCrypto::new(1),
            },
            b: Node {
                fsm: QlFsm::new(config, identity_b, time),
                crypto: TestCrypto::new(2),
            },
        };

        harness.a.fsm.bind_peer(peer_a);
        harness.b.fsm.bind_peer(peer_b);
        while harness.a.fsm.take_next_event().is_some() {}
        while harness.b.fsm.take_next_event().is_some() {}

        harness
    }

    fn connected(config: QlFsmConfig) -> Self {
        let mut harness = Self::paired(config);
        let session_key = SymmetricKey::from_data([7; SymmetricKey::SYMMETRIC_KEY_SIZE]);

        harness.a.fsm.peer.as_mut().unwrap().session = ConnectionState::Connected {
            session_key: session_key.clone(),
            recent_ready: None,
        };
        harness.b.fsm.peer.as_mut().unwrap().session = ConnectionState::Connected {
            session_key,
            recent_ready: None,
        };
        harness.a.fsm.session = SessionFsm::new(
            SessionFsmConfig {
                local_namespace: StreamNamespace::for_local(
                    harness.a.fsm.identity.xid,
                    harness.a.fsm.peer.as_ref().unwrap().peer.xid,
                ),
                ack_delay: config.session_ack_delay,
                retransmit_timeout: config.session_retransmit_timeout,
                keepalive_interval: config.session_keepalive_interval,
                peer_timeout: config.session_peer_timeout,
            },
            harness.now,
        );
        harness.b.fsm.session = SessionFsm::new(
            SessionFsmConfig {
                local_namespace: StreamNamespace::for_local(
                    harness.b.fsm.identity.xid,
                    harness.b.fsm.peer.as_ref().unwrap().peer.xid,
                ),
                ack_delay: config.session_ack_delay,
                retransmit_timeout: config.session_retransmit_timeout,
                keepalive_interval: config.session_keepalive_interval,
                peer_timeout: config.session_peer_timeout,
            },
            harness.now,
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

    fn next_outbound_a(&mut self) -> Option<QlRecord> {
        let write = self.a.fsm.take_next_write(self.time(), &self.a.crypto)?;
        if let Some(id) = write.session_write_id {
            self.a.fsm.confirm_session_write(self.time(), id);
        }
        Some(write.record)
    }

    fn next_outbound_b(&mut self) -> Option<QlRecord> {
        let write = self.b.fsm.take_next_write(self.time(), &self.b.crypto)?;
        if let Some(id) = write.session_write_id {
            self.b.fsm.confirm_session_write(self.time(), id);
        }
        Some(write.record)
    }

    fn next_write_a(&mut self) -> Option<OutboundWrite> {
        self.a.fsm.take_next_write(self.time(), &self.a.crypto)
    }

    fn deliver_to_a(&mut self, record: QlRecord) {
        self.a
            .fsm
            .receive(self.time(), ql_wire::encode_record(&record), &self.a.crypto)
            .unwrap();
    }

    fn deliver_to_b(&mut self, record: QlRecord) {
        self.b
            .fsm
            .receive(self.time(), ql_wire::encode_record(&record), &self.b.crypto)
            .unwrap();
    }

    fn confirm_write_a(&mut self, write_id: SessionWriteId) {
        self.a.fsm.confirm_session_write(self.time(), write_id);
    }

    fn return_write_a(&mut self, write_id: SessionWriteId) {
        self.a.fsm.reject_session_write(write_id);
    }

    fn pump(&mut self) {
        for _ in 0..128 {
            let mut progressed = false;

            while let Some(record) = self.next_outbound_a() {
                progressed = true;
                self.deliver_to_b(record);
            }

            while let Some(record) = self.next_outbound_b() {
                progressed = true;
                self.deliver_to_a(record);
            }

            if !progressed {
                return;
            }
        }

        panic!("pump did not quiesce");
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
        xid: identity.xid,
        signing_key: identity.signing_public_key.clone(),
        encapsulation_key: identity.encapsulation_public_key.clone(),
    }
}

fn decrypt_envelope(record: &QlRecord, session_key: &SymmetricKey) -> ql_wire::SessionEnvelope {
    let aad = record.header.aad();
    let QlPayload::Encrypted(encrypted) = &record.payload else {
        panic!("expected encrypted payload");
    };
    let plaintext = encrypted.decrypt(session_key, &aad).unwrap();
    let archived =
        rkyv::access::<ql_wire::encrypted::ArchivedSessionEnvelope, rkyv::rancor::Error>(
            &plaintext,
        )
        .unwrap();
    low::deserialize::<ql_wire::SessionEnvelope, rkyv::rancor::Error>(archived).unwrap()
}
