mod handshake;
mod proptest;
mod session;

use std::{
    cell::Cell,
    collections::VecDeque,
    time::{Duration, Instant},
};

use libcrux_aesgcm::AesGcm256Key;
use libcrux_ml_kem::mlkem1024;
use ql_wire::{
    self, generate_identity, ConnectionId, MlKemCiphertext, MlKemKeyPair, MlKemPrivateKey,
    MlKemPublicKey, Nonce, PairingToken, QlAead, QlCrypto, QlHash, QlIdentity, QlKem, QlRandom,
    SessionKey, TransportParams, ENCRYPTED_MESSAGE_AUTH_SIZE, XID,
};
use sha2::{Digest, Sha256};

use crate::{
    session::{SessionFsm, SessionFsmConfig, StreamParity},
    state::{ConnectedState, LinkState, SessionTransport},
    FsmTime, OutboundWrite, QlFsm, QlFsmConfig, QlFsmError, QlFsmEvent, SessionWriteId,
};

#[derive(Clone)]
struct TestCrypto {
    seed: u8,
    counter: Cell<u64>,
}

impl TestCrypto {
    fn new(seed: u8) -> Self {
        Self {
            seed,
            counter: Cell::new(0),
        }
    }

    fn next_block(&self) -> [u8; 32] {
        let counter = self.counter.get();
        self.counter.set(counter.wrapping_add(1));
        sha256_parts(&[b"ql-fsm:test-rng:v1", &[self.seed], &counter.to_le_bytes()])
    }

    fn random_array<const L: usize>(&self) -> [u8; L] {
        let mut out = [0u8; L];
        self.fill_random_bytes(&mut out);
        out
    }
}

impl QlRandom for TestCrypto {
    fn fill_random_bytes(&self, out: &mut [u8]) {
        fill_expanded(self, &[b"ql-fsm:test-fill:v1"], out);
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

struct Node {
    fsm: QlFsm,
    crypto: TestCrypto,
    events: VecDeque<QlFsmEvent>,
}

struct Harness {
    now: Instant,
    unix_secs: u64,
    a: Node,
    b: Node,
}

impl Harness {
    fn paired_known(config: QlFsmConfig) -> Self {
        Self::paired_with_configs(config, config, true, true)
    }

    fn paired(config: QlFsmConfig, know_a: bool, know_b: bool) -> Self {
        Self::paired_with_configs(config, config, know_a, know_b)
    }

    fn paired_known_with_configs(config_a: QlFsmConfig, config_b: QlFsmConfig) -> Self {
        Self::paired_with_configs(config_a, config_b, true, true)
    }

    fn paired_with_configs(
        config_a: QlFsmConfig,
        config_b: QlFsmConfig,
        know_a: bool,
        know_b: bool,
    ) -> Self {
        let identity_a = test_identity(11);
        let identity_b = test_identity(73);
        let now = Instant::now();
        let time = FsmTime {
            instant: now,
            unix_secs: 1_700_000_000,
        };

        let mut harness = Self {
            now,
            unix_secs: time.unix_secs,
            a: Node {
                fsm: QlFsm::new(config_a, identity_a.clone(), time),
                crypto: TestCrypto::new(1),
                events: Default::default(),
            },
            b: Node {
                fsm: QlFsm::new(config_b, identity_b.clone(), time),
                crypto: TestCrypto::new(2),
                events: Default::default(),
            },
        };

        if know_a {
            harness.a.fsm.bind_peer(identity_b.bundle());
        }
        if know_b {
            harness.b.fsm.bind_peer(identity_a.bundle());
        }

        harness
    }

    fn connected(config: QlFsmConfig) -> Self {
        let mut harness = Self::paired_known(config);
        let a_to_b_key = SessionKey::from_data([7; SessionKey::SIZE]);
        let b_to_a_key = SessionKey::from_data([9; SessionKey::SIZE]);
        let a_to_b_conn = ConnectionId::from_data([0xA1; ConnectionId::SIZE]);
        let b_to_a_conn = ConnectionId::from_data([0xB2; ConnectionId::SIZE]);

        harness.a.fsm.state.link = LinkState::Connected(ConnectedState {
            transport: SessionTransport {
                tx_key: a_to_b_key.clone(),
                rx_key: b_to_a_key.clone(),
                tx_connection_id: a_to_b_conn,
                rx_connection_id: b_to_a_conn,
                remote_transport_params: TransportParams {
                    initial_stream_receive_window: harness
                        .b
                        .fsm
                        .config
                        .session_stream_receive_buffer_size,
                },
            },
            session: SessionFsm::new(session_config(&harness, true), harness.now),
        });
        harness.b.fsm.state.link = LinkState::Connected(ConnectedState {
            transport: SessionTransport {
                tx_key: b_to_a_key,
                rx_key: a_to_b_key,
                tx_connection_id: b_to_a_conn,
                rx_connection_id: a_to_b_conn,
                remote_transport_params: TransportParams {
                    initial_stream_receive_window: harness
                        .a
                        .fsm
                        .config
                        .session_stream_receive_buffer_size,
                },
            },
            session: SessionFsm::new(session_config(&harness, false), harness.now),
        });
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

    fn next_outbound_a(&mut self) -> Option<Vec<u8>> {
        let write = self.a.fsm.take_next_write(self.time(), &self.a.crypto)?;
        if let Some(id) = write.session_write_id {
            self.a.fsm.confirm_session_write(self.time(), id);
        }
        Some(write.record)
    }

    fn next_outbound_b(&mut self) -> Option<Vec<u8>> {
        let write = self.b.fsm.take_next_write(self.time(), &self.b.crypto)?;
        if let Some(id) = write.session_write_id {
            self.b.fsm.confirm_session_write(self.time(), id);
        }
        Some(write.record)
    }

    fn next_write_a(&mut self) -> Option<OutboundWrite> {
        self.a.fsm.take_next_write(self.time(), &self.a.crypto)
    }

    fn connect_ik_a(&mut self) -> Result<(), QlFsmError> {
        let time = self.time();
        let Node {
            fsm,
            crypto,
            events,
        } = &mut self.a;
        fsm.connect_ik(time, crypto, |event| events.push_back(event))
    }

    fn connect_ik_b(&mut self) -> Result<(), QlFsmError> {
        let time = self.time();
        let Node {
            fsm,
            crypto,
            events,
        } = &mut self.b;
        fsm.connect_ik(time, crypto, |event| events.push_back(event))
    }

    fn connect_kk_a(&mut self) -> Result<(), QlFsmError> {
        let time = self.time();
        let Node {
            fsm,
            crypto,
            events,
        } = &mut self.a;
        fsm.connect_kk(time, crypto, |event| events.push_back(event))
    }

    fn connect_kk_b(&mut self) -> Result<(), QlFsmError> {
        let time = self.time();
        let Node {
            fsm,
            crypto,
            events,
        } = &mut self.b;
        fsm.connect_kk(time, crypto, |event| events.push_back(event))
    }

    fn connect_xx_a(&mut self, token: PairingToken) -> Result<(), QlFsmError> {
        let time = self.time();
        let Node {
            fsm,
            crypto,
            events,
        } = &mut self.a;
        fsm.connect_xx(time, token, crypto, |event| events.push_back(event))
    }

    fn connect_xx_b(&mut self, token: PairingToken) -> Result<(), QlFsmError> {
        let time = self.time();
        let Node {
            fsm,
            crypto,
            events,
        } = &mut self.b;
        fsm.connect_xx(time, token, crypto, |event| events.push_back(event))
    }

    fn accept_pairing_a(&mut self, token: PairingToken) -> Result<(), QlFsmError> {
        let time = self.time();
        let Node {
            fsm,
            crypto,
            events,
        } = &mut self.a;
        fsm.accept_pairing(time, token, crypto, |event| events.push_back(event))
    }

    fn accept_pairing_b(&mut self, token: PairingToken) -> Result<(), QlFsmError> {
        let time = self.time();
        let Node {
            fsm,
            crypto,
            events,
        } = &mut self.b;
        fsm.accept_pairing(time, token, crypto, |event| events.push_back(event))
    }

    fn reject_pairing_b(&mut self, token: PairingToken) -> Result<(), QlFsmError> {
        self.b.fsm.reject_pairing(token)
    }

    fn deliver_to_a(&mut self, record: Vec<u8>) {
        let time = self.time();
        let Node {
            fsm,
            crypto,
            events,
        } = &mut self.a;
        fsm.receive(time, record, crypto, |event| events.push_back(event))
            .unwrap();
    }

    fn deliver_to_b(&mut self, record: Vec<u8>) {
        let time = self.time();
        let Node {
            fsm,
            crypto,
            events,
        } = &mut self.b;
        fsm.receive(time, record, crypto, |event| events.push_back(event))
            .unwrap();
    }

    fn confirm_write_a(&mut self, write_id: SessionWriteId) {
        self.a.fsm.confirm_session_write(self.time(), write_id);
    }

    fn return_write_a(&mut self, write_id: SessionWriteId) {
        self.a.fsm.reject_session_write(write_id);
    }

    fn on_timer_a(&mut self) {
        let time = self.time();
        let Node { fsm, events, .. } = &mut self.a;
        fsm.on_timer(time, |event| events.push_back(event));
    }

    fn on_timer_b(&mut self) {
        let time = self.time();
        let Node { fsm, events, .. } = &mut self.b;
        fsm.on_timer(time, |event| events.push_back(event));
    }

    fn take_event_a(&mut self) -> Option<QlFsmEvent> {
        self.a.events.pop_front()
    }

    fn take_event_b(&mut self) -> Option<QlFsmEvent> {
        self.b.events.pop_front()
    }

    fn drain_events_a(&mut self) -> Vec<QlFsmEvent> {
        self.a.events.drain(..).collect()
    }

    fn drain_events_b(&mut self) -> Vec<QlFsmEvent> {
        self.b.events.drain(..).collect()
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
    generate_identity(&crypto, XID([seed; XID::SIZE]))
}

fn pairing_token(byte: u8) -> PairingToken {
    PairingToken([byte; PairingToken::SIZE])
}

fn session_config(harness: &Harness, a: bool) -> SessionFsmConfig {
    let (local, peer, config) = if a {
        (
            harness.a.fsm.identity.xid,
            harness.a.fsm.state.peer.as_ref().unwrap().xid,
            harness.a.fsm.config,
        )
    } else {
        (
            harness.b.fsm.identity.xid,
            harness.b.fsm.state.peer.as_ref().unwrap().xid,
            harness.b.fsm.config,
        )
    };

    SessionFsmConfig {
        local_parity: StreamParity::for_local(local, peer),
        record_max_size: config.session_record_max_size,
        ack_delay: config.session_record_ack_delay,
        retransmit_timeout: config.session_record_retransmit_timeout,
        keepalive_interval: config.session_keepalive_interval,
        peer_timeout: config.session_peer_timeout,
        stream_send_buffer_size: config.session_stream_send_buffer_size,
        stream_receive_buffer_size: config.session_stream_receive_buffer_size,
        initial_peer_stream_receive_window: if a {
            harness.b.fsm.config.session_stream_receive_buffer_size
        } else {
            harness.a.fsm.config.session_stream_receive_buffer_size
        },
    }
}

fn decrypt_record(
    crypto: &impl QlCrypto,
    record: &[u8],
    session_key: &SessionKey,
) -> (ql_wire::SessionHeader, Vec<ql_wire::SessionFrame<Vec<u8>>>) {
    let (_header, record) =
        ql_wire::decode_record::<ql_wire::QlSessionRecord<_>, _>(record).unwrap();
    let plaintext = ql_wire::decrypt_record(
        crypto,
        &record.header,
        record.payload.into_owned(),
        session_key,
    )
    .unwrap();
    (
        record.header,
        ql_wire::decode_session_frames(&plaintext).unwrap(),
    )
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
        inputs.push(b"ql-fsm:test-expand:v1".as_slice());
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
