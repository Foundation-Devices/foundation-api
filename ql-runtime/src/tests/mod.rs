use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::Duration,
};

use async_channel::{Receiver, Sender};
use ql_fsm::PeerStatus;
use ql_wire::{
    test_identities, test_identity, MlKemCiphertext, MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey,
    Nonce, PairingToken, PeerBundle, QlAead, QlHash, QlIdentity, QlKem, QlRandom, RecordHeader,
    RecordType, RouteId, SessionKey, SoftwareCrypto, WireDecode, XID,
};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    A,
    B,
}

impl Side {
    fn opposite(self) -> Self {
        match self {
            Side::A => Side::B,
            Side::B => Side::A,
        }
    }
}

fn test_route_id() -> RouteId {
    RouteId::from_u32(1)
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

struct TestPlatform {
    outbound: Sender<Vec<u8>>,
    status: Sender<StatusEvent>,
    inbound: Option<Sender<QlStream>>,
    crypto: SoftwareCrypto,
    encrypted_write_counter: AtomicUsize,
    fail_encrypted_write_at: Option<usize>,
    write_delay: Duration,
    write_stats: Option<WriteStats>,
}

impl TestPlatform {
    fn new() -> (Self, Receiver<Vec<u8>>, Receiver<StatusEvent>) {
        Self::new_inner(None, None, Duration::ZERO, None)
    }

    fn new_with_inbound() -> (
        Self,
        Receiver<Vec<u8>>,
        Receiver<StatusEvent>,
        Receiver<QlStream>,
    ) {
        let (inbound_tx, inbound_rx) = async_channel::unbounded();
        let (platform, outbound_rx, status_rx) =
            Self::new_inner(Some(inbound_tx), None, Duration::ZERO, None);
        (platform, outbound_rx, status_rx, inbound_rx)
    }

    fn new_with_session_write_failure(
        fail_encrypted_write_at: usize,
    ) -> (Self, Receiver<Vec<u8>>, Receiver<StatusEvent>) {
        Self::new_inner(None, Some(fail_encrypted_write_at), Duration::ZERO, None)
    }

    fn new_with_delayed_writes(
        delay: Duration,
        write_stats: WriteStats,
    ) -> (Self, Receiver<Vec<u8>>, Receiver<StatusEvent>) {
        Self::new_inner(None, None, delay, Some(write_stats))
    }

    fn new_inner(
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
                crypto: SoftwareCrypto,
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

struct TestSide {
    handle: RuntimeHandle,
    status: Receiver<StatusEvent>,
    peer: XID,
    inbound: Receiver<QlStream>,
}

struct TestPair {
    a: TestSide,
    b: TestSide,
}

#[derive(Debug, Clone, Copy, Default)]
struct LinkBehavior {
    base_delay: Duration,
    drop_encrypted_every: Option<usize>,
    duplicate_encrypted_every: Option<usize>,
    delay_encrypted_every: Option<(usize, Duration)>,
}

#[derive(Clone, Default)]
struct LinkController {
    behavior: Arc<Mutex<LinkBehavior>>,
}

impl LinkController {
    fn new(behavior: LinkBehavior) -> Self {
        Self {
            behavior: Arc::new(Mutex::new(behavior)),
        }
    }

    fn load(&self) -> LinkBehavior {
        *self.behavior.lock().unwrap()
    }

    fn store(&self, behavior: LinkBehavior) {
        *self.behavior.lock().unwrap() = behavior;
    }
}

#[derive(Clone)]
struct ControlledLinks {
    a_to_b: LinkController,
    b_to_a: LinkController,
}

impl TestPair {
    fn new(config: RuntimeConfig) -> Self {
        Self::new_with_links(config, LinkBehavior::default(), LinkBehavior::default())
    }

    fn new_with_links(config: RuntimeConfig, a_to_b: LinkBehavior, b_to_a: LinkBehavior) -> Self {
        let (pair, _links) = Self::new_with_controlled_links(config, a_to_b, b_to_a);
        pair
    }

    fn new_with_controlled_links(
        config: RuntimeConfig,
        a_to_b: LinkBehavior,
        b_to_a: LinkBehavior,
    ) -> (Self, ControlledLinks) {
        let (platform_a, outbound_a, status_a, inbound_a) = TestPlatform::new_with_inbound();
        let (platform_b, outbound_b, status_b, inbound_b) = TestPlatform::new_with_inbound();
        let (identity_a, identity_b) = test_identities(&SoftwareCrypto);
        let links = ControlledLinks {
            a_to_b: LinkController::new(a_to_b),
            b_to_a: LinkController::new(b_to_a),
        };

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config.clone());
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_simulated_forwarder(outbound_a, handle_b.clone(), links.a_to_b.clone());
        spawn_simulated_forwarder(outbound_b, handle_a.clone(), links.b_to_a.clone());
        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);

        (
            Self {
                a: TestSide {
                    handle: handle_a,
                    status: status_a,
                    peer: identity_a.xid,
                    inbound: inbound_a,
                },
                b: TestSide {
                    handle: handle_b,
                    status: status_b,
                    peer: identity_b.xid,
                    inbound: inbound_b,
                },
            },
            links,
        )
    }

    fn side(&self, side: Side) -> &TestSide {
        match side {
            Side::A => &self.a,
            Side::B => &self.b,
        }
    }

    fn handle(&self, side: Side) -> &RuntimeHandle {
        &self.side(side).handle
    }

    fn side_mut(&mut self, side: Side) -> &mut TestSide {
        match side {
            Side::A => &mut self.a,
            Side::B => &mut self.b,
        }
    }

    async fn connect_and_wait(&self, initiator: Side) {
        self.side(initiator).handle.connect();
        await_status(
            &self.side(initiator).status,
            self.side(initiator.opposite()).peer,
            PeerStatus::Connected,
        )
        .await;
        await_status(
            &self.side(initiator.opposite()).status,
            self.side(initiator).peer,
            PeerStatus::Connected,
        )
        .await;
    }

    fn take_inbound(&mut self, side: Side) -> Receiver<QlStream> {
        let replacement = async_channel::unbounded().1;
        std::mem::replace(&mut self.side_mut(side).inbound, replacement)
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
        self.crypto.fill_random_bytes(data);
    }
}

impl QlHash for TestPlatform {
    fn sha256(&self, parts: &[&[u8]]) -> [u8; 32] {
        self.crypto.sha256(parts)
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
        self.crypto.aes256_gcm_encrypt(key, nonce, aad, buffer)
    }

    fn aes256_gcm_decrypt(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
        auth_tag: &[u8; ql_wire::ENCRYPTED_MESSAGE_AUTH_SIZE],
    ) -> bool {
        self.crypto
            .aes256_gcm_decrypt(key, nonce, aad, buffer, auth_tag)
    }
}

impl QlKem for TestPlatform {
    fn mlkem_generate_keypair(&self) -> MlKemKeyPair {
        self.crypto.mlkem_generate_keypair()
    }

    fn mlkem_encapsulate(&self, public_key: &MlKemPublicKey) -> (MlKemCiphertext, SessionKey) {
        self.crypto.mlkem_encapsulate(public_key)
    }

    fn mlkem_decapsulate(&self, pk: &MlKemPrivateKey, cipher: &MlKemCiphertext) -> SessionKey {
        self.crypto.mlkem_decapsulate(pk, cipher)
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

fn pairing_token(byte: u8) -> PairingToken {
    PairingToken([byte; PairingToken::SIZE])
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
    spawn_simulated_forwarder(
        outbound,
        handle,
        LinkController::new(LinkBehavior::default()),
    );
}

fn spawn_simulated_forwarder(
    outbound: Receiver<Vec<u8>>,
    handle: RuntimeHandle,
    controller: LinkController,
) {
    tokio::task::spawn_local(async move {
        let mut encrypted_count = 0usize;
        while let Ok(bytes) = outbound.recv().await {
            let behavior = controller.load();
            let encrypted = is_encrypted_payload(&bytes);
            let ordinal = if encrypted {
                encrypted_count = encrypted_count.saturating_add(1);
                Some(encrypted_count)
            } else {
                None
            };

            if ordinal.is_some_and(|count| {
                behavior
                    .drop_encrypted_every
                    .is_some_and(|nth| nth != 0 && count % nth == 0)
            }) {
                continue;
            }

            let mut delay = behavior.base_delay;
            if let Some(count) = ordinal {
                if let Some((nth, extra_delay)) = behavior.delay_encrypted_every {
                    if nth != 0 && count % nth == 0 {
                        delay += extra_delay;
                    }
                }
            }

            let primary = bytes.clone();
            let primary_handle = handle.clone();
            tokio::task::spawn_local(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                primary_handle.receive(primary);
            });

            if ordinal.is_some_and(|count| {
                behavior
                    .duplicate_encrypted_every
                    .is_some_and(|nth| nth != 0 && count % nth == 0)
            }) {
                let duplicate_handle = handle.clone();
                tokio::task::spawn_local(async move {
                    let duplicate_delay = delay + Duration::from_millis(1);
                    if !duplicate_delay.is_zero() {
                        tokio::time::sleep(duplicate_delay).await;
                    }
                    duplicate_handle.receive(bytes);
                });
            }
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
            handle.receive(bytes);
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
            handle.receive(bytes);
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

#[allow(clippy::future_not_send)]
async fn run_local_test_timeout<F>(duration: Duration, future: F)
where
    F: Future<Output = ()>,
{
    tokio::time::timeout(duration, run_local_test(future))
        .await
        .unwrap_or_else(|_| panic!("local runtime test exceeded {:?}", duration));
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
    let identity_a = test_identity(&SoftwareCrypto);
    let (platform_a, _, _) = TestPlatform::new();
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
    let identity = test_identity(&SoftwareCrypto);
    let (platform, _, _) = TestPlatform::new();
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
