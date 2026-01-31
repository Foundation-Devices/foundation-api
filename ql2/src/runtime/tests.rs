use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};

use async_channel::{Receiver, Sender};
use bc_components::{
    EncapsulationPrivateKey, EncapsulationPublicKey, EncapsulationScheme, SignatureScheme, Signer,
    SigningPrivateKey, SigningPublicKey, SymmetricKey, XID,
};
use dcbor::CBOR;
use tokio::{sync::Semaphore, task::LocalSet};

use crate::{
    crypto::{handshake, heartbeat, pair},
    platform::{PlatformFuture, QlPlatform},
    runtime::{
        internal::now_secs, new_runtime, HandlerEvent, KeepAliveConfig, PeerSession, RequestConfig,
        RuntimeConfig, RuntimeHandle,
    },
    wire::{
        handshake::HandshakeRecord, heartbeat::HeartbeatBody, message::Nack, QlHeader, QlPayload,
        QlRecord,
    },
    MessageId, QlError, RouteId,
};

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

struct TestPlatform {
    signing_private: SigningPrivateKey,
    signing_public: SigningPublicKey,
    encapsulation_private: EncapsulationPrivateKey,
    encapsulation_public: EncapsulationPublicKey,
    outbound: Sender<Vec<u8>>,
    status: Sender<StatusEvent>,
    nonce_seed: u8,
    nonce_counter: AtomicU8,
}

impl TestPlatform {
    fn new(seed: u8) -> (Self, Receiver<Vec<u8>>, Receiver<StatusEvent>) {
        let (signing_private, signing_public) = SignatureScheme::MLDSA44.keypair();
        let (encapsulation_private, encapsulation_public) =
            EncapsulationScheme::default().keypair();
        let (outbound, outbound_rx) = async_channel::unbounded();
        let (status, status_rx) = async_channel::unbounded();
        (
            Self {
                signing_private,
                signing_public,
                encapsulation_private,
                encapsulation_public,
                outbound,
                status,
                nonce_seed: seed,
                nonce_counter: AtomicU8::new(0),
            },
            outbound_rx,
            status_rx,
        )
    }

    fn signing_public_key(&self) -> &SigningPublicKey {
        &self.signing_public
    }

    fn encapsulation_public_key(&self) -> &EncapsulationPublicKey {
        &self.encapsulation_public
    }
}

impl QlPlatform for TestPlatform {
    fn signer(&self) -> &dyn Signer {
        &self.signing_private
    }

    fn signing_public_key(&self) -> &SigningPublicKey {
        &self.signing_public
    }

    fn encapsulation_private_key(&self) -> &EncapsulationPrivateKey {
        &self.encapsulation_private
    }

    fn encapsulation_public_key(&self) -> &EncapsulationPublicKey {
        &self.encapsulation_public
    }

    fn fill_bytes(&self, data: &mut [u8]) {
        let value = self
            .nonce_seed
            .wrapping_add(self.nonce_counter.fetch_add(1, Ordering::Relaxed));
        data.fill(value);
    }

    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>> {
        let outbound = self.outbound.clone();
        Box::pin(async move {
            outbound
                .send(message)
                .await
                .map_err(|_| QlError::InvalidPayload)
        })
    }

    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn handle_peer_status(&self, peer: XID, session: &PeerSession) {
        let stage = match session {
            PeerSession::Disconnected => PeerStage::Disconnected,
            PeerSession::Initiator { .. } => PeerStage::Initiator,
            PeerSession::Responder { .. } => PeerStage::Responder,
            PeerSession::Connected { .. } => PeerStage::Connected,
        };
        let _ = self.status.try_send(StatusEvent { peer, stage });
    }

    fn handle_inbound(&self, _event: crate::runtime::HandlerEvent) {}
}

struct BlockingPlatform {
    signing_private: SigningPrivateKey,
    signing_public: SigningPublicKey,
    encapsulation_private: EncapsulationPrivateKey,
    encapsulation_public: EncapsulationPublicKey,
    outbound: Sender<Vec<u8>>,
    status: Sender<StatusEvent>,
    nonce_seed: u8,
    nonce_counter: AtomicU8,
    write_gate: Arc<Semaphore>,
}

struct InboundPlatform {
    signing_private: SigningPrivateKey,
    signing_public: SigningPublicKey,
    encapsulation_private: EncapsulationPrivateKey,
    encapsulation_public: EncapsulationPublicKey,
    outbound: Sender<Vec<u8>>,
    status: Sender<StatusEvent>,
    inbound: Sender<HandlerEvent>,
    nonce_seed: u8,
    nonce_counter: AtomicU8,
}

impl InboundPlatform {
    fn new(
        seed: u8,
    ) -> (
        Self,
        Receiver<Vec<u8>>,
        Receiver<StatusEvent>,
        Receiver<HandlerEvent>,
    ) {
        let (signing_private, signing_public) = SignatureScheme::MLDSA44.keypair();
        let (encapsulation_private, encapsulation_public) =
            EncapsulationScheme::default().keypair();
        let (outbound, outbound_rx) = async_channel::unbounded();
        let (status, status_rx) = async_channel::unbounded();
        let (inbound, inbound_rx) = async_channel::unbounded();
        (
            Self {
                signing_private,
                signing_public,
                encapsulation_private,
                encapsulation_public,
                outbound,
                status,
                inbound,
                nonce_seed: seed,
                nonce_counter: AtomicU8::new(0),
            },
            outbound_rx,
            status_rx,
            inbound_rx,
        )
    }

    fn signing_public_key(&self) -> &SigningPublicKey {
        &self.signing_public
    }

    fn encapsulation_public_key(&self) -> &EncapsulationPublicKey {
        &self.encapsulation_public
    }
}

impl QlPlatform for InboundPlatform {
    fn signer(&self) -> &dyn Signer {
        &self.signing_private
    }

    fn signing_public_key(&self) -> &SigningPublicKey {
        &self.signing_public
    }

    fn encapsulation_private_key(&self) -> &EncapsulationPrivateKey {
        &self.encapsulation_private
    }

    fn encapsulation_public_key(&self) -> &EncapsulationPublicKey {
        &self.encapsulation_public
    }

    fn fill_bytes(&self, data: &mut [u8]) {
        let value = self
            .nonce_seed
            .wrapping_add(self.nonce_counter.fetch_add(1, Ordering::Relaxed));
        data.fill(value);
    }

    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>> {
        let outbound = self.outbound.clone();
        Box::pin(async move {
            outbound
                .send(message)
                .await
                .map_err(|_| QlError::InvalidPayload)
        })
    }

    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn handle_peer_status(&self, peer: XID, session: &PeerSession) {
        let stage = match session {
            PeerSession::Disconnected => PeerStage::Disconnected,
            PeerSession::Initiator { .. } => PeerStage::Initiator,
            PeerSession::Responder { .. } => PeerStage::Responder,
            PeerSession::Connected { .. } => PeerStage::Connected,
        };
        let _ = self.status.try_send(StatusEvent { peer, stage });
    }

    fn handle_inbound(&self, event: HandlerEvent) {
        let _ = self.inbound.try_send(event);
    }
}

impl BlockingPlatform {
    fn new(
        seed: u8,
    ) -> (
        Self,
        Receiver<Vec<u8>>,
        Receiver<StatusEvent>,
        Arc<Semaphore>,
    ) {
        let (signing_private, signing_public) = SignatureScheme::MLDSA44.keypair();
        let (encapsulation_private, encapsulation_public) =
            EncapsulationScheme::default().keypair();
        let (outbound, outbound_rx) = async_channel::unbounded();
        let (status, status_rx) = async_channel::unbounded();
        let write_gate = Arc::new(Semaphore::new(0));
        (
            Self {
                signing_private,
                signing_public,
                encapsulation_private,
                encapsulation_public,
                outbound,
                status,
                nonce_seed: seed,
                nonce_counter: AtomicU8::new(0),
                write_gate: write_gate.clone(),
            },
            outbound_rx,
            status_rx,
            write_gate,
        )
    }

    fn signing_public_key(&self) -> &SigningPublicKey {
        &self.signing_public
    }

    fn encapsulation_public_key(&self) -> &EncapsulationPublicKey {
        &self.encapsulation_public
    }
}

impl QlPlatform for BlockingPlatform {
    fn signer(&self) -> &dyn Signer {
        &self.signing_private
    }

    fn signing_public_key(&self) -> &SigningPublicKey {
        &self.signing_public
    }

    fn encapsulation_private_key(&self) -> &EncapsulationPrivateKey {
        &self.encapsulation_private
    }

    fn encapsulation_public_key(&self) -> &EncapsulationPublicKey {
        &self.encapsulation_public
    }

    fn fill_bytes(&self, data: &mut [u8]) {
        let value = self
            .nonce_seed
            .wrapping_add(self.nonce_counter.fetch_add(1, Ordering::Relaxed));
        data.fill(value);
    }

    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>> {
        let outbound = self.outbound.clone();
        let write_gate = self.write_gate.clone();
        Box::pin(async move {
            let _permit = write_gate.acquire().await.expect("write gate closed");
            outbound
                .send(message)
                .await
                .map_err(|_| QlError::InvalidPayload)
        })
    }

    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn handle_peer_status(&self, peer: XID, session: &PeerSession) {
        let stage = match session {
            PeerSession::Disconnected => PeerStage::Disconnected,
            PeerSession::Initiator { .. } => PeerStage::Initiator,
            PeerSession::Responder { .. } => PeerStage::Responder,
            PeerSession::Connected { .. } => PeerStage::Connected,
        };
        let _ = self.status.try_send(StatusEvent { peer, stage });
    }

    fn handle_inbound(&self, _event: crate::runtime::HandlerEvent) {}
}

async fn run_local_test<F>(future: F)
where
    F: Future<Output = ()>,
{
    let local = LocalSet::new();
    local.run_until(future).await;
}

fn spawn_forwarder(outbound: Receiver<Vec<u8>>, handle: RuntimeHandle) {
    tokio::task::spawn_local(async move {
        while let Ok(bytes) = outbound.recv().await {
            let _ = handle.send_incoming(bytes);
        }
    });
}

fn is_heartbeat(bytes: &[u8]) -> bool {
    let Ok(record) = CBOR::try_from_data(bytes).and_then(QlRecord::try_from) else {
        return false;
    };
    matches!(record.payload, QlPayload::Heartbeat(_))
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
            let _ = handle.send_incoming(bytes);
        }
    });
}

fn spawn_drop_heartbeat_forwarder(outbound: Receiver<Vec<u8>>, handle: RuntimeHandle) {
    tokio::task::spawn_local(async move {
        while let Ok(bytes) = outbound.recv().await {
            if is_heartbeat(&bytes) {
                continue;
            }
            let _ = handle.send_incoming(bytes);
        }
    });
}

fn spawn_gated_forwarder(
    outbound: Receiver<Vec<u8>>,
    handle: RuntimeHandle,
    drop_flag: Arc<AtomicBool>,
) {
    tokio::task::spawn_local(async move {
        while let Ok(bytes) = outbound.recv().await {
            if drop_flag.load(Ordering::Relaxed) {
                continue;
            }
            let _ = handle.send_incoming(bytes);
        }
    });
}

async fn await_status(
    receiver: &Receiver<StatusEvent>,
    peer: XID,
    stage: PeerStage,
) -> StatusEvent {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(event) = receiver.recv().await {
                if event.peer == peer && event.stage == stage {
                    return event;
                }
            }
        }
    })
    .await
    .expect("status timeout")
}

#[tokio::test(flavor = "current_thread")]
async fn handshake_initiator_connects() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) =
            new_runtime(platform_b, RuntimeConfig::new(Duration::from_millis(200)));

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_drop_heartbeat_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn handshake_timeout_disconnects() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(50));
        let (platform_a, _outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, _outbound_b, _status_b) = TestPlatform::new(2);

        let signing_b = platform_b.signing_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_b = XID::new(&signing_b);
        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        tokio::task::spawn_local(async move { runtime_a.run().await });

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Disconnected).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn simultaneous_handshakes_resolve() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) =
            new_runtime(platform_b, RuntimeConfig::new(Duration::from_millis(200)));

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();
        handle_b.connect(peer_a).unwrap();

        await_status(&status_a, peer_b, PeerStage::Initiator).await;
        await_status(&status_b, peer_a, PeerStage::Responder).await;
        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_signature_disconnects() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, _status_b) = TestPlatform::new(2);
        let (wrong_private, wrong_public) = SignatureScheme::MLDSA44.keypair();
        let _ = wrong_private;

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) =
            new_runtime(platform_b, RuntimeConfig::new(Duration::from_millis(200)));

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(peer_b, wrong_public, encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Disconnected).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn pairing_request_triggers_handshake() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let pairing_message = pair::build_pair_request(
            &platform_a,
            peer_b,
            &encap_b,
            MessageId::new(1),
            Duration::from_secs(1),
        )
        .expect("pairing request");
        let pairing_bytes = CBOR::from(pairing_message).to_cbor_data();

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) =
            new_runtime(platform_b, RuntimeConfig::new(Duration::from_millis(200)));

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());

        handle_b.send_incoming(pairing_bytes);

        await_status(&status_b, peer_a, PeerStage::Initiator).await;
        await_status(&status_a, peer_b, PeerStage::Responder).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;
        await_status(&status_a, peer_b, PeerStage::Connected).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn request_response_round_trip() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_request_timeout(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config.clone());
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let inbound_task = tokio::task::spawn_local(async move {
            if let Ok(HandlerEvent::Request(request)) = inbound_b.recv().await {
                let _ = request.respond_to.respond(99u8);
            }
        });

        let response = handle_a.send_request_raw(
            peer_b,
            RouteId::new(7),
            CBOR::from(12u8),
            RequestConfig::default(),
        );

        let response = response.recv().await.unwrap();
        let value: u8 = response.try_into().unwrap();
        assert_eq!(value, 99u8);
        let _ = inbound_task.await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn request_timeout_returns_error() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_request_timeout(Duration::from_millis(30));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config.clone());
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let ticket = handle_a.send_request_raw(
            peer_b,
            RouteId::new(1),
            CBOR::from(1u8),
            RequestConfig {
                timeout: Some(Duration::from_millis(30)),
            },
        );

        let result = tokio::time::timeout(Duration::from_millis(200), ticket.recv())
            .await
            .expect("timeout wait");
        assert!(matches!(result, Err(QlError::Timeout)));
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn request_nack_resolves_pending() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_request_timeout(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config.clone());
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let inbound_task = tokio::task::spawn_local(async move {
            if let Ok(HandlerEvent::Request(request)) = inbound_b.recv().await {
                let _ = request.respond_to.respond_nack(Nack::InvalidPayload);
            }
        });

        let response = handle_a.send_request_raw(
            peer_b,
            RouteId::new(2),
            CBOR::from(2u8),
            RequestConfig::default(),
        );

        let result = response.recv().await;
        assert!(matches!(
            result,
            Err(QlError::Nack {
                nack: Nack::InvalidPayload,
                ..
            })
        ));
        let _ = inbound_task.await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn request_dispatches_to_platform_callback() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_request_timeout(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config.clone());
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let inbound_task = tokio::task::spawn_local(async move {
            if let Ok(HandlerEvent::Request(request)) = inbound_b.recv().await {
                let _ = request.respond_to.respond(7u8);
            }
        });

        let ticket = handle_a.send_request_raw(
            peer_b,
            RouteId::new(3),
            CBOR::from(1u8),
            RequestConfig::default(),
        );

        let response = ticket.recv().await.unwrap();
        let value: u8 = response.try_into().unwrap();
        assert_eq!(value, 7u8);
        let _ = inbound_task.await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn blocked_write_still_times_out() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(40));
        let (platform_a, _outbound_a, status_a, _write_gate) = BlockingPlatform::new(2);
        let (platform_b, _outbound_b, _status_b) = TestPlatform::new(1);

        let signing_b = platform_b.signing_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        tokio::task::spawn_local(async move { runtime_a.run().await });

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Initiator).await;
        await_status(&status_a, peer_b, PeerStage::Disconnected).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn handshake_timeout_drops_queued_messages() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(60));
        let (platform_a, outbound_a, status_a, write_gate) = BlockingPlatform::new(2);
        let (platform_b, _outbound_b, _status_b) = TestPlatform::new(1);

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        tokio::task::spawn_local(async move { runtime_a.run().await });

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());

        handle_a.connect(peer_b).unwrap();
        await_status(&status_a, peer_b, PeerStage::Initiator).await;

        let (hello, _secret) =
            handshake::build_hello(&platform_b, peer_b, peer_a, &encap_a).expect("hello build");
        let message = QlRecord {
            header: QlHeader {
                sender: peer_b,
                recipient: peer_a,
            },
            payload: QlPayload::Handshake(HandshakeRecord::Hello(hello)),
        };
        let bytes = CBOR::from(message).to_cbor_data();
        handle_a.send_incoming(bytes);

        await_status(&status_a, peer_b, PeerStage::Responder).await;
        await_status(&status_a, peer_b, PeerStage::Disconnected).await;

        write_gate.add_permits(1);
        let _ = tokio::time::timeout(Duration::from_millis(100), outbound_a.recv())
            .await
            .expect("hello write")
            .expect("outbound closed");

        write_gate.add_permits(1);
        let second = tokio::time::timeout(Duration::from_millis(50), outbound_a.recv()).await;
        assert!(
            second.is_err(),
            "expected queued handshake reply to be dropped"
        );
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn heartbeat_ignored_without_session() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, _status_a) = TestPlatform::new(1);
        let (platform_b, _outbound_b, _status_b) = TestPlatform::new(2);

        let signing_b = platform_b.signing_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(platform_a.signing_public_key());
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        tokio::task::spawn_local(async move { runtime_a.run().await });

        handle_a.register_peer(peer_b, signing_b, encap_b);

        let heartbeat = heartbeat::encrypt_heartbeat(
            QlHeader {
                sender: peer_b,
                recipient: peer_a,
            },
            &SymmetricKey::new(),
            HeartbeatBody {
                message_id: MessageId::new(1),
                valid_until: now_secs().saturating_add(60),
            },
        );
        let bytes = CBOR::from(heartbeat).to_cbor_data();
        handle_a.send_incoming(bytes);

        let result = tokio::time::timeout(Duration::from_millis(50), outbound_a.recv()).await;
        assert!(result.is_err(), "expected heartbeat to be ignored");
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn keepalive_disabled_no_heartbeat() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_tx, heartbeat_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_tx);
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let result = tokio::time::timeout(Duration::from_millis(120), heartbeat_rx.recv()).await;
        assert!(result.is_err(), "unexpected heartbeat while disabled");
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn heartbeat_sent_after_idle() {
    run_local_test(async {
        let keep_alive = KeepAliveConfig {
            interval: Duration::from_millis(30),
            timeout: Duration::from_millis(80),
        };
        let config_a = RuntimeConfig::new(Duration::from_millis(200)).with_keep_alive(keep_alive);
        let config_b = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_tx, heartbeat_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_tx);
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let _ = tokio::time::timeout(Duration::from_millis(200), heartbeat_rx.recv())
            .await
            .expect("heartbeat timeout")
            .expect("heartbeat channel closed");
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn heartbeat_reply_when_connected() {
    run_local_test(async {
        let keep_alive = KeepAliveConfig {
            interval: Duration::from_millis(30),
            timeout: Duration::from_millis(80),
        };
        let config_a = RuntimeConfig::new(Duration::from_millis(200)).with_keep_alive(keep_alive);
        let config_b = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_ab_tx, heartbeat_ab_rx) = async_channel::unbounded();
        let (heartbeat_ba_tx, heartbeat_ba_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_ab_tx);
        spawn_heartbeat_tap_forwarder(outbound_b, handle_a.clone(), heartbeat_ba_tx);

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let _ = tokio::time::timeout(Duration::from_millis(200), heartbeat_ab_rx.recv())
            .await
            .expect("heartbeat request timeout")
            .expect("heartbeat channel closed");
        let _ = tokio::time::timeout(Duration::from_millis(200), heartbeat_ba_rx.recv())
            .await
            .expect("heartbeat reply timeout")
            .expect("heartbeat channel closed");
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn any_message_clears_pending() {
    run_local_test(async {
        let keep_alive = KeepAliveConfig {
            interval: Duration::from_millis(120),
            timeout: Duration::from_millis(40),
        };
        let config_a = RuntimeConfig::new(Duration::from_millis(200)).with_keep_alive(keep_alive);
        let config_b = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_tx, heartbeat_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_tx);
        spawn_drop_heartbeat_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let _ = tokio::time::timeout(Duration::from_millis(200), heartbeat_rx.recv())
            .await
            .expect("heartbeat request timeout")
            .expect("heartbeat channel closed");

        handle_b.send_event_raw(peer_a, RouteId::new(99), CBOR::from(1u8));

        let window = keep_alive.timeout + Duration::from_millis(20);
        let disconnect = tokio::time::timeout(window, async {
            loop {
                if let Ok(event) = status_a.recv().await {
                    if event.peer == peer_b && event.stage == PeerStage::Disconnected {
                        return;
                    }
                }
            }
        })
        .await;
        assert!(disconnect.is_err(), "unexpected disconnect");
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn heartbeat_timeout_disconnects_and_drops_outbound() {
    run_local_test(async {
        let keep_alive = KeepAliveConfig {
            interval: Duration::from_millis(80),
            timeout: Duration::from_millis(60),
        };
        let config_a = RuntimeConfig::new(Duration::from_millis(200)).with_keep_alive(keep_alive);
        let config_b = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(2);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(1);

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let drop_flag = Arc::new(AtomicBool::new(false));
        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_gated_forwarder(outbound_b, handle_a.clone(), drop_flag.clone());

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        drop_flag.store(true, Ordering::Relaxed);

        let response = handle_a.send_request_raw(
            peer_b,
            RouteId::new(9),
            CBOR::from(9u8),
            RequestConfig {
                timeout: Some(Duration::from_millis(200)),
            },
        );

        await_status(&status_a, peer_b, PeerStage::Disconnected).await;

        let result = tokio::time::timeout(Duration::from_millis(300), response.recv())
            .await
            .expect("response wait");
        assert!(
            matches!(result, Err(QlError::SendFailed)),
            "unexpected result: {result:?}"
        );
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn no_ping_pong() {
    run_local_test(async {
        let keep_alive = KeepAliveConfig {
            interval: Duration::from_millis(200),
            timeout: Duration::from_millis(60),
        };
        let config_a = RuntimeConfig::new(Duration::from_millis(200)).with_keep_alive(keep_alive);
        let config_b = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_ab_tx, heartbeat_ab_rx) = async_channel::unbounded();
        let (heartbeat_ba_tx, heartbeat_ba_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_ab_tx);
        spawn_heartbeat_tap_forwarder(outbound_b, handle_a.clone(), heartbeat_ba_tx);

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let _ = tokio::time::timeout(Duration::from_millis(300), heartbeat_ab_rx.recv())
            .await
            .expect("heartbeat request timeout")
            .expect("heartbeat channel closed");
        let _ = tokio::time::timeout(Duration::from_millis(200), heartbeat_ba_rx.recv())
            .await
            .expect("heartbeat reply timeout")
            .expect("heartbeat channel closed");

        let followup =
            tokio::time::timeout(Duration::from_millis(50), heartbeat_ab_rx.recv()).await;
        assert!(followup.is_err(), "unexpected heartbeat ping-pong");
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_heartbeat_ignored() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_tx, heartbeat_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_tx);
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let heartbeat = heartbeat::encrypt_heartbeat(
            QlHeader {
                sender: peer_b,
                recipient: peer_a,
            },
            &SymmetricKey::new(),
            HeartbeatBody {
                message_id: MessageId::new(42),
                valid_until: now_secs().saturating_add(30),
            },
        );
        let bytes = CBOR::from(heartbeat).to_cbor_data();
        handle_a.send_incoming(bytes);

        let result = tokio::time::timeout(Duration::from_millis(50), heartbeat_rx.recv()).await;
        assert!(result.is_err(), "unexpected heartbeat reply");
    })
    .await;
}
