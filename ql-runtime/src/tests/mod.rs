use std::{
    future::Future,
    sync::{
        atomic::{AtomicU8, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use async_channel::{Receiver, Sender};
use bc_components::{MLDSA, MLKEM};
use tokio::task::LocalSet;

use crate::{
    engine::QlCrypto,
    identity::QlIdentity,
    new_runtime,
    platform::PlatformFuture,
    wire::{self, QlPayload},
    HandlerEvent, KeepAliveConfig, Peer, PeerSession, QlError, RuntimeConfig, RuntimeHandle,
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
    peer: bc_components::XID,
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

struct TestPlatform {
    outbound: Sender<Vec<u8>>,
    status: Sender<StatusEvent>,
    inbound: Option<Sender<HandlerEvent>>,
    nonce_seed: u8,
    nonce_counter: AtomicU8,
    stream_write_counter: AtomicUsize,
    fail_stream_write_at: Option<usize>,
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
        Receiver<HandlerEvent>,
    ) {
        let (inbound_tx, inbound_rx) = async_channel::unbounded();
        let (platform, outbound_rx, status_rx) =
            Self::new_inner(seed, Some(inbound_tx), None, Duration::ZERO, None);
        (platform, outbound_rx, status_rx, inbound_rx)
    }

    fn new_with_stream_write_failure(
        seed: u8,
        fail_stream_write_at: usize,
    ) -> (Self, Receiver<Vec<u8>>, Receiver<StatusEvent>) {
        Self::new_inner(seed, None, Some(fail_stream_write_at), Duration::ZERO, None)
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
        inbound: Option<Sender<HandlerEvent>>,
        fail_stream_write_at: Option<usize>,
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
                stream_write_counter: AtomicUsize::new(0),
                fail_stream_write_at,
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
}

impl crate::platform::QlPlatform for TestPlatform {
    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>> {
        let outbound = self.outbound.clone();
        let write_delay = self.write_delay;
        let fail_stream_write_at = self.fail_stream_write_at;
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
            if is_stream_payload(&message) {
                let count = self.stream_write_counter.fetch_add(1, Ordering::Relaxed) + 1;
                should_fail = fail_stream_write_at == Some(count);
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

    fn handle_peer_status(&self, peer: bc_components::XID, session: &PeerSession) {
        let stage = match session {
            PeerSession::Disconnected => PeerStage::Disconnected,
            PeerSession::Initiator { .. } => PeerStage::Initiator,
            PeerSession::Responder { .. } => PeerStage::Responder,
            PeerSession::Connected { .. } => PeerStage::Connected,
        };
        let _ = self.status.try_send(StatusEvent { peer, stage });
    }

    fn handle_inbound(&self, event: HandlerEvent) {
        if let Some(tx) = &self.inbound {
            let _ = tx.try_send(event);
        }
    }
}

fn is_stream_payload(bytes: &[u8]) -> bool {
    wire::decode_record(bytes)
        .ok()
        .is_some_and(|record| matches!(record.payload, QlPayload::Stream(_)))
}

fn new_identity() -> QlIdentity {
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
        peer: identity.xid,
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

fn spawn_drop_every_nth_stream_forwarder(
    outbound: Receiver<Vec<u8>>,
    handle: RuntimeHandle,
    nth: usize,
) {
    tokio::task::spawn_local(async move {
        let mut stream_count = 0usize;
        while let Ok(bytes) = outbound.recv().await {
            if nth > 0 && is_stream_payload(&bytes) {
                stream_count = stream_count.saturating_add(1);
                if stream_count % nth == 0 {
                    continue;
                }
            }
            handle.send_incoming(bytes);
        }
    });
}

fn is_heartbeat(bytes: &[u8]) -> bool {
    wire::decode_record(bytes)
        .ok()
        .is_some_and(|record| matches!(record.payload, QlPayload::Heartbeat(_)))
}

fn spawn_heartbeat_tap_forwarder(
    outbound: Receiver<Vec<u8>>,
    handle: RuntimeHandle,
    heartbeat_tx: Sender<()>,
) {
    tokio::task::spawn_local(async move {
        while let Ok(bytes) = outbound.recv().await {
            if is_heartbeat(&bytes) {
                let _ = heartbeat_tx.send(()).await;
            }
            handle.send_incoming(bytes);
        }
    });
}

fn spawn_drop_heartbeat_forwarder(outbound: Receiver<Vec<u8>>, handle: RuntimeHandle) {
    tokio::task::spawn_local(async move {
        while let Ok(bytes) = outbound.recv().await {
            if is_heartbeat(&bytes) {
                continue;
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

async fn await_status(
    receiver: &Receiver<StatusEvent>,
    peer: bc_components::XID,
    stage: PeerStage,
) {
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
    peer: bc_components::XID,
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

async fn read_all(mut stream: crate::InboundByteStream) -> Result<Vec<u8>, QlError> {
    let mut data = Vec::new();
    while let Some(chunk) = stream.next_chunk().await? {
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

fn default_runtime_config() -> RuntimeConfig {
    RuntimeConfig {
        engine: crate::engine::EngineConfig {
            handshake_timeout: Duration::from_millis(300),
            stream_ack_timeout: Duration::from_millis(30),
            stream_retry_limit: 8,
            ..Default::default()
        },
        ..Default::default()
    }
}
