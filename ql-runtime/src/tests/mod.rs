use std::{
    cell::Cell,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU8, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use async_channel::{Receiver, Sender};
use libcrux_aesgcm::AesGcm256Key;
use ql_fsm::PeerStatus;
use ql_wire::{
    generate_identity, MlKemCiphertext, MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey, Nonce,
    PeerBundle, QlAead, QlHash, QlIdentity, QlKem, QlRandom, RecordHeader, RecordType, SessionKey,
    WireDecode, XID,
};
use sha2::{Digest, Sha256};
use tokio::{task::LocalSet, time::Sleep};

use crate::{
    new_runtime,
    platform::{PlatformFuture, QlTimer},
    NoSessionError, QlFsmConfig, QlStream, QlStreamError, RuntimeConfig, RuntimeHandle,
};

mod handshake;
mod heartbeat;
#[cfg(feature = "rpc")]
mod rpc;
mod stream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatusEvent {
    peer: XID,
    status: PeerStatus,
}

#[derive(Debug, Clone)]
struct WriteStats {
    active: Arc<AtomicUsize>,
    max_active: Arc<AtomicUsize>,
}

impl WriteStats {
    fn new() -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
            max_active: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn max_active(&self) -> usize {
        self.max_active.load(Ordering::Relaxed)
    }
}

struct DeterministicCrypto {
    seed: u8,
    counter: Cell<u8>,
}

impl DeterministicCrypto {
    fn new(seed: u8) -> Self {
        Self {
            seed,
            counter: Cell::new(0),
        }
    }
}

impl QlRandom for DeterministicCrypto {
    fn fill_random_bytes(&self, data: &mut [u8]) {
        let value = self.seed.wrapping_add(self.counter.get());
        self.counter.set(self.counter.get().wrapping_add(1));
        data.fill(value);
    }
}

impl QlHash for DeterministicCrypto {
    fn sha256(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().into()
    }
}

impl QlAead for DeterministicCrypto {
    fn aes256_gcm_encrypt(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> [u8; ql_wire::ENCRYPTED_MESSAGE_AUTH_SIZE] {
        let key: AesGcm256Key = (*key.data()).into();
        let plaintext = buffer.to_vec();
        let mut auth = [0u8; ql_wire::ENCRYPTED_MESSAGE_AUTH_SIZE];
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
        auth_tag: &[u8; ql_wire::ENCRYPTED_MESSAGE_AUTH_SIZE],
    ) -> bool {
        let key: AesGcm256Key = (*key.data()).into();
        let ciphertext = buffer.to_vec();
        key.decrypt(buffer, (&nonce.0).into(), aad, &ciphertext, auth_tag.into())
            .is_ok()
    }
}

impl QlKem for DeterministicCrypto {
    fn mlkem_generate_keypair(&self) -> MlKemKeyPair {
        let data = Box::new([self.seed; MlKemPublicKey::SIZE]);
        MlKemKeyPair {
            private: MlKemPrivateKey::new(Box::new([self.seed; MlKemPrivateKey::SIZE])),
            public: MlKemPublicKey::new(data),
        }
    }

    fn mlkem_encapsulate(&self, public_key: &MlKemPublicKey) -> (MlKemCiphertext, SessionKey) {
        let mut secret = [0u8; SessionKey::SIZE];
        secret.copy_from_slice(&public_key.as_bytes()[..SessionKey::SIZE]);
        (
            MlKemCiphertext::new(Box::new([self.seed; MlKemCiphertext::SIZE])),
            SessionKey::from_data(secret),
        )
    }

    fn mlkem_decapsulate(
        &self,
        private_key: &MlKemPrivateKey,
        _ciphertext: &MlKemCiphertext,
    ) -> SessionKey {
        let mut secret = [0u8; SessionKey::SIZE];
        secret.copy_from_slice(&private_key.as_bytes()[..SessionKey::SIZE]);
        SessionKey::from_data(secret)
    }
}

struct TestPlatform {
    outbound: Sender<Vec<u8>>,
    status: Sender<StatusEvent>,
    inbound: Option<Sender<QlStream>>,
    nonce_seed: u8,
    nonce_counter: AtomicU8,
    encrypted_write_counter: AtomicUsize,
    fail_encrypted_write_at: Option<usize>,
    write_delay: Duration,
    write_stats: Option<WriteStats>,
}

impl TestPlatform {
    fn new(seed: u8) -> (Self, Receiver<Vec<u8>>, Receiver<StatusEvent>) {
        Self::new_inner(seed, None, None, Duration::ZERO, None)
    }

    fn new_with_inbound(
        seed: u8,
    ) -> (
        Self,
        Receiver<Vec<u8>>,
        Receiver<StatusEvent>,
        Receiver<QlStream>,
    ) {
        let (inbound_tx, inbound_rx) = async_channel::unbounded();
        let (platform, outbound_rx, status_rx) =
            Self::new_inner(seed, Some(inbound_tx), None, Duration::ZERO, None);
        (platform, outbound_rx, status_rx, inbound_rx)
    }

    fn new_with_session_write_failure(
        seed: u8,
        fail_encrypted_write_at: usize,
    ) -> (Self, Receiver<Vec<u8>>, Receiver<StatusEvent>) {
        Self::new_inner(
            seed,
            None,
            Some(fail_encrypted_write_at),
            Duration::ZERO,
            None,
        )
    }

    fn new_with_delayed_writes(
        seed: u8,
        delay: Duration,
        write_stats: WriteStats,
    ) -> (Self, Receiver<Vec<u8>>, Receiver<StatusEvent>) {
        Self::new_inner(seed, None, None, delay, Some(write_stats))
    }

    fn new_inner(
        seed: u8,
        inbound: Option<Sender<QlStream>>,
        fail_encrypted_write_at: Option<usize>,
        write_delay: Duration,
        write_stats: Option<WriteStats>,
    ) -> (Self, Receiver<Vec<u8>>, Receiver<StatusEvent>) {
        let (outbound, outbound_rx) = async_channel::unbounded();
        let (status, status_rx) = async_channel::unbounded();
        (
            Self {
                outbound,
                status,
                inbound,
                nonce_seed: seed,
                nonce_counter: AtomicU8::new(0),
                encrypted_write_counter: AtomicUsize::new(0),
                fail_encrypted_write_at,
                write_delay,
                write_stats,
            },
            outbound_rx,
            status_rx,
        )
    }
}

struct TokioTimer {
    sleep: Pin<Box<Sleep>>,
}

impl TokioTimer {
    fn new() -> Self {
        Self {
            sleep: Box::pin(tokio::time::sleep_until(parked_deadline())),
        }
    }
}

impl QlTimer for TokioTimer {
    fn set_deadline(&mut self, deadline: Option<std::time::Instant>) {
        let deadline = deadline.map_or_else(parked_deadline, tokio::time::Instant::from_std);
        self.sleep.as_mut().reset(deadline);
    }

    fn poll_wait(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.sleep.as_mut().poll(cx)
    }
}

impl QlRandom for TestPlatform {
    fn fill_random_bytes(&self, data: &mut [u8]) {
        let value = self
            .nonce_seed
            .wrapping_add(self.nonce_counter.fetch_add(1, Ordering::Relaxed));
        data.fill(value);
    }
}

impl QlHash for TestPlatform {
    fn sha256(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().into()
    }
}

impl QlAead for TestPlatform {
    fn aes256_gcm_encrypt(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> [u8; ql_wire::ENCRYPTED_MESSAGE_AUTH_SIZE] {
        let key: AesGcm256Key = (*key.data()).into();
        let plaintext = buffer.to_vec();
        let mut auth = [0u8; ql_wire::ENCRYPTED_MESSAGE_AUTH_SIZE];
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
        auth_tag: &[u8; ql_wire::ENCRYPTED_MESSAGE_AUTH_SIZE],
    ) -> bool {
        let key: AesGcm256Key = (*key.data()).into();
        let ciphertext = buffer.to_vec();
        key.decrypt(buffer, (&nonce.0).into(), aad, &ciphertext, auth_tag.into())
            .is_ok()
    }
}

impl QlKem for TestPlatform {
    fn mlkem_generate_keypair(&self) -> MlKemKeyPair {
        let byte = self.nonce_seed;
        MlKemKeyPair {
            private: MlKemPrivateKey::new(Box::new([byte; MlKemPrivateKey::SIZE])),
            public: MlKemPublicKey::new(Box::new([byte; MlKemPublicKey::SIZE])),
        }
    }

    fn mlkem_encapsulate(&self, public_key: &MlKemPublicKey) -> (MlKemCiphertext, SessionKey) {
        let mut secret = [0u8; SessionKey::SIZE];
        secret.copy_from_slice(&public_key.as_bytes()[..SessionKey::SIZE]);
        (
            MlKemCiphertext::new(Box::new([self.nonce_seed; MlKemCiphertext::SIZE])),
            SessionKey::from_data(secret),
        )
    }

    fn mlkem_decapsulate(
        &self,
        private_key: &MlKemPrivateKey,
        _ciphertext: &MlKemCiphertext,
    ) -> SessionKey {
        let mut secret = [0u8; SessionKey::SIZE];
        secret.copy_from_slice(&private_key.as_bytes()[..SessionKey::SIZE]);
        SessionKey::from_data(secret)
    }
}

impl crate::platform::QlPlatform for TestPlatform {
    type Timer = TokioTimer;
    type WriteMessageFut<'a> = PlatformFuture<'a, bool>;

    fn write_message(&self, message: Vec<u8>) -> Self::WriteMessageFut<'_> {
        let outbound = self.outbound.clone();
        let write_delay = self.write_delay;
        let fail_encrypted_write_at = self.fail_encrypted_write_at;
        let write_stats = self.write_stats.clone();

        Box::pin(async move {
            if let Some(stats) = write_stats.as_ref() {
                let active = stats.active.fetch_add(1, Ordering::Relaxed) + 1;
                stats.max_active.fetch_max(active, Ordering::Relaxed);
            }

            if !write_delay.is_zero() {
                tokio::time::sleep(write_delay).await;
            }

            let should_fail = if is_encrypted_payload(&message) {
                let count = self.encrypted_write_counter.fetch_add(1, Ordering::Relaxed) + 1;
                fail_encrypted_write_at == Some(count)
            } else {
                false
            };

            let success = if should_fail {
                false
            } else {
                outbound.send(message).await.is_ok()
            };

            if let Some(stats) = write_stats.as_ref() {
                stats.active.fetch_sub(1, Ordering::Relaxed);
            }

            success
        })
    }

    fn timer(&self) -> Self::Timer {
        TokioTimer::new()
    }

    fn load_peer(&self) -> PlatformFuture<'_, Option<PeerBundle>> {
        Box::pin(async { None })
    }

    fn persist_peer(&self, _peer: PeerBundle) {}

    fn handle_peer_status(&self, peer: XID, status: PeerStatus) {
        let _ = self.status.try_send(StatusEvent { peer, status });
    }

    fn handle_inbound(&self, event: QlStream) {
        if let Some(tx) = &self.inbound {
            let _ = tx.try_send(event);
        }
    }
}

fn parked_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(60 * 60 * 24 * 365 * 100)
}

fn is_encrypted_payload(bytes: &[u8]) -> bool {
    RecordHeader::decode_bytes(bytes)
        .ok()
        .is_some_and(|header| header.record_type == RecordType::Session)
}

pub(crate) fn new_identity(seed: u8) -> QlIdentity {
    let crypto = DeterministicCrypto::new(seed);
    generate_identity(&crypto, XID([seed; XID::SIZE]))
}

fn register_peers(
    handle_a: &RuntimeHandle,
    handle_b: &RuntimeHandle,
    id_a: &QlIdentity,
    id_b: &QlIdentity,
) {
    handle_a.bind_peer(id_b.bundle());
    handle_b.bind_peer(id_a.bundle());
}

fn spawn_forwarder(outbound: Receiver<Vec<u8>>, handle: RuntimeHandle) {
    tokio::task::spawn_local(async move {
        while let Ok(bytes) = outbound.recv().await {
            handle.send_incoming(bytes);
        }
    });
}

fn spawn_drop_every_nth_encrypted_forwarder(
    outbound: Receiver<Vec<u8>>,
    handle: RuntimeHandle,
    nth: usize,
) {
    tokio::task::spawn_local(async move {
        let mut encrypted_count = 0usize;
        while let Ok(bytes) = outbound.recv().await {
            if nth > 0 && is_encrypted_payload(&bytes) {
                encrypted_count = encrypted_count.saturating_add(1);
                if encrypted_count % nth == 0 {
                    continue;
                }
            }
            handle.send_incoming(bytes);
        }
    });
}

fn spawn_gated_forwarder(
    outbound: Receiver<Vec<u8>>,
    handle: RuntimeHandle,
    drop_flag: Arc<std::sync::atomic::AtomicBool>,
) {
    tokio::task::spawn_local(async move {
        while let Ok(bytes) = outbound.recv().await {
            if drop_flag.load(Ordering::Relaxed) {
                continue;
            }
            handle.send_incoming(bytes);
        }
    });
}

#[allow(clippy::future_not_send)]
async fn run_local_test<F>(future: F)
where
    F: Future<Output = ()>,
{
    let local = LocalSet::new();
    local.run_until(future).await;
}

async fn await_status(receiver: &Receiver<StatusEvent>, peer: XID, stage: PeerStatus) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(event) = receiver.recv().await {
                if event.peer == peer && event.status == stage {
                    return;
                }
            }
        }
    })
    .await
    .unwrap();
}

async fn assert_no_status_for(
    receiver: &Receiver<StatusEvent>,
    peer: XID,
    status: PeerStatus,
    window: Duration,
) {
    let res = tokio::time::timeout(window, async {
        loop {
            let event = receiver.recv().await.unwrap();
            if event.peer == peer && event.status == status {
                return;
            }
        }
    })
    .await;
    assert!(res.is_err(), "unexpected status event: {status:?}");
}

async fn read_all(mut stream: crate::ByteReader) -> Result<Vec<u8>, QlStreamError> {
    let mut data = Vec::new();
    while let Some(chunk) = next_chunk(&mut stream).await? {
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

async fn next_chunk_max(
    stream: &mut crate::ByteReader,
    max_len: usize,
) -> Result<Option<Vec<u8>>, crate::QlStreamError> {
    stream
        .read(max_len)
        .await
        .map(|chunk| chunk.map(|bytes| bytes.to_vec()))
}

async fn next_chunk(stream: &mut crate::ByteReader) -> Result<Option<Vec<u8>>, QlStreamError> {
    next_chunk_max(stream, usize::MAX).await
}

fn default_runtime_config() -> RuntimeConfig {
    RuntimeConfig {
        fsm: QlFsmConfig {
            handshake_timeout: Duration::from_millis(300),
            session_record_retransmit_timeout: Duration::from_millis(30),
            session_keepalive_interval: Duration::ZERO,
            session_peer_timeout: Duration::ZERO,
            ..Default::default()
        },
        ..Default::default()
    }
}

// runtime is send, though the Runtime::run future itself is not
#[test]
fn runtime_is_send() {
    let config = default_runtime_config();
    let identity_a = new_identity(11);
    let (platform_a, _, _) = TestPlatform::new(1);
    let (runtime_a, _handle) = new_runtime(identity_a, platform_a, config);
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(runtime_a.run());
    });
}

#[test]
fn runtime_exits_when_last_handle_drops() {
    let config = default_runtime_config();
    let identity = new_identity(11);
    let (platform, _, _) = TestPlatform::new(1);
    let (runtime, handle) = new_runtime(identity, platform, config);
    let (done_tx, done_rx) = oneshot::channel();

    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(runtime.run());
        done_tx.send(()).unwrap();
    });

    drop(handle);

    done_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("runtime should stop once the last sender is dropped");
}
