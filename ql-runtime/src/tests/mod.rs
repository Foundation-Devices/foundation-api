use std::{
    cell::Cell,
    future::Future,
    sync::{
        atomic::{AtomicU8, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use async_channel::{Receiver, Sender};
use libcrux_aesgcm::AesGcm256Key;
use ql_wire::{
    generate_ml_dsa_keypair, generate_ml_kem_keypair, EncryptedMessage, Nonce, QlCrypto,
    QlIdentity, QlPayload, QlRecord, SessionKey, XID,
};
use sha2::{Digest, Sha256};
use tokio::task::LocalSet;

use crate::{
    new_runtime, platform::PlatformFuture, InboundStream, Peer, PeerStatus, QlError, QlFsmConfig,
    RuntimeConfig, RuntimeHandle,
};

mod handshake;
mod heartbeat;
mod stream;
mod unpair;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerStage {
    Disconnected,
    Initiator,
    Responder,
    Connected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatusEvent {
    peer: XID,
    stage: PeerStage,
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

impl QlCrypto for DeterministicCrypto {
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
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Option<[u8; EncryptedMessage::AUTH_SIZE]> {
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
        .ok()?;
        Some(auth)
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

struct TestPlatform {
    outbound: Sender<Vec<u8>>,
    status: Sender<StatusEvent>,
    inbound: Option<Sender<InboundStream>>,
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
        Receiver<InboundStream>,
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
        inbound: Option<Sender<InboundStream>>,
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

impl QlCrypto for TestPlatform {
    fn fill_random_bytes(&self, data: &mut [u8]) {
        let value = self
            .nonce_seed
            .wrapping_add(self.nonce_counter.fetch_add(1, Ordering::Relaxed));
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
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Option<[u8; EncryptedMessage::AUTH_SIZE]> {
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
        .ok()?;
        Some(auth)
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

impl crate::platform::QlPlatform for TestPlatform {
    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>> {
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

            let mut should_fail = false;
            if is_encrypted_payload(&message) {
                let count = self.encrypted_write_counter.fetch_add(1, Ordering::Relaxed) + 1;
                should_fail = fail_encrypted_write_at == Some(count);
            }

            let result = if should_fail {
                Err(QlError::SendFailed)
            } else {
                outbound
                    .send(message)
                    .await
                    .map_err(|_| QlError::InvalidPayload)
            };

            if let Some(stats) = write_stats.as_ref() {
                stats.active.fetch_sub(1, Ordering::Relaxed);
            }

            result
        })
    }

    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn load_peer(&self) -> PlatformFuture<'_, Option<Peer>> {
        Box::pin(async { None })
    }

    fn persist_peer(&self, _peer: Peer) {}

    fn clear_peer(&self) {}

    fn handle_peer_status(&self, peer: XID, status: PeerStatus) {
        let stage = match status {
            PeerStatus::Disconnected => PeerStage::Disconnected,
            PeerStatus::Initiator => PeerStage::Initiator,
            PeerStatus::Responder => PeerStage::Responder,
            PeerStatus::Connected => PeerStage::Connected,
        };
        let _ = self.status.try_send(StatusEvent { peer, stage });
    }

    fn handle_inbound(&self, event: InboundStream) {
        if let Some(tx) = &self.inbound {
            let _ = tx.try_send(event);
        }
    }
}

fn is_encrypted_payload(bytes: &[u8]) -> bool {
    QlRecord::decode(bytes)
        .ok()
        .is_some_and(|record| matches!(record.payload, QlPayload::Session(_)))
}

pub(crate) fn new_identity(seed: u8) -> QlIdentity {
    let crypto = DeterministicCrypto::new(seed);
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

fn register_peers(
    handle_a: &RuntimeHandle,
    handle_b: &RuntimeHandle,
    id_a: &QlIdentity,
    id_b: &QlIdentity,
) {
    handle_a.bind_peer(peer_from_identity(id_b));
    handle_b.bind_peer(peer_from_identity(id_a));
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

async fn run_local_test<F>(future: F)
where
    F: Future<Output = ()>,
{
    let local = LocalSet::new();
    local.run_until(future).await;
}

async fn await_status(receiver: &Receiver<StatusEvent>, peer: XID, stage: PeerStage) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(event) = receiver.recv().await {
                if event.peer == peer && event.stage == stage {
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
    stage: PeerStage,
    window: Duration,
) {
    let res = tokio::time::timeout(window, async {
        loop {
            let event = receiver.recv().await.unwrap();
            if event.peer == peer && event.stage == stage {
                return;
            }
        }
    })
    .await;
    assert!(res.is_err(), "unexpected status event: {stage:?}");
}

async fn read_all(mut stream: crate::ByteReader) -> Result<Vec<u8>, QlError> {
    let mut data = Vec::new();
    while let Some(chunk) = stream.next_chunk().await? {
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

fn default_runtime_config() -> RuntimeConfig {
    RuntimeConfig {
        fsm: QlFsmConfig {
            handshake_timeout: Duration::from_millis(300),
            session_retransmit_timeout: Duration::from_millis(30),
            session_keepalive_interval: Duration::ZERO,
            session_peer_timeout: Duration::ZERO,
            ..Default::default()
        },
        ..Default::default()
    }
}
