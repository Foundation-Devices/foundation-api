mod handshake;
mod session;

use std::{
    cell::Cell,
    time::{Duration, Instant},
};

use libcrux_aesgcm::AesGcm256Key;
use ql_wire::{
    self, generate_ml_dsa_keypair, generate_ml_kem_keypair, QlCrypto, QlIdentity, QlPayload,
    QlRecord, SessionKey, XID, ENCRYPTED_MESSAGE_AUTH_SIZE,
};
use sha2::{Digest, Sha256};

use crate::{
    session::{state::StreamParity, SessionFsm, SessionFsmConfig},
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
        nonce: &ql_wire::Nonce,
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

    fn decrypt_with_aead(
        &self,
        key: &SessionKey,
        nonce: &ql_wire::Nonce,
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
        let identity_a = test_identity(11);
        let identity_b = test_identity(73);
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
        let session_key = SessionKey::from_data([7; SessionKey::SIZE]);

        harness.a.fsm.peer.as_mut().unwrap().session = ConnectionState::Connected {
            session_key,
            recent_ready: None,
        };
        harness.b.fsm.peer.as_mut().unwrap().session = ConnectionState::Connected {
            session_key,
            recent_ready: None,
        };
        harness.a.fsm.session = SessionFsm::new(
            SessionFsmConfig {
                local_parity: StreamParity::for_local(
                    harness.a.fsm.identity.xid,
                    harness.a.fsm.peer.as_ref().unwrap().peer.xid,
                ),
                record_size: config.session_record_size,
                ack_delay: config.session_record_ack_delay,
                retransmit_timeout: config.session_record_retransmit_timeout,
                keepalive_interval: config.session_keepalive_interval,
                peer_timeout: config.session_peer_timeout,
                stream_send_buffer_size: config.session_stream_send_buffer_size,
                stream_receive_buffer_size: config.session_stream_receive_buffer_size,
            },
            harness.now,
        );
        harness.b.fsm.session = SessionFsm::new(
            SessionFsmConfig {
                local_parity: StreamParity::for_local(
                    harness.b.fsm.identity.xid,
                    harness.b.fsm.peer.as_ref().unwrap().peer.xid,
                ),
                record_size: config.session_record_size,
                ack_delay: config.session_record_ack_delay,
                retransmit_timeout: config.session_record_retransmit_timeout,
                keepalive_interval: config.session_keepalive_interval,
                peer_timeout: config.session_peer_timeout,
                stream_send_buffer_size: config.session_stream_send_buffer_size,
                stream_receive_buffer_size: config.session_stream_receive_buffer_size,
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
            .receive(self.time(), record.encode(), &self.a.crypto)
            .unwrap();
    }

    fn deliver_to_b(&mut self, record: QlRecord) {
        self.b
            .fsm
            .receive(self.time(), record.encode(), &self.b.crypto)
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

fn test_identity(seed: u8) -> QlIdentity {
    let crypto = TestCrypto::new(seed);
    let (signing_private, signing_public) = generate_ml_dsa_keypair(&crypto);
    let (encapsulation_private, encapsulation_public) = generate_ml_kem_keypair(&crypto);
    QlIdentity::new(
        XID([seed; XID::SIZE]),
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

fn decrypt_record(
    crypto: &impl QlCrypto,
    record: &QlRecord,
    session_key: &SessionKey,
) -> ql_wire::SessionRecord {
    let aad = record.header.aad();
    let QlPayload::Session(encrypted) = &record.payload else {
        panic!("expected encrypted payload");
    };
    let plaintext = encrypted.decrypt(crypto, session_key, &aad).unwrap();
    ql_wire::SessionRecord::decode(&plaintext).unwrap()
}
