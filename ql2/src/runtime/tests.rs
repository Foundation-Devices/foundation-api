use std::{
    future::Future,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};

use async_channel::{Receiver, Sender};
use bc_components::{
    EncapsulationPrivateKey, EncapsulationPublicKey, EncapsulationScheme, SignatureScheme,
    SigningPrivateKey, SigningPublicKey, Signer, XID,
};
use dcbor::CBOR;
use tokio::{sync::Semaphore, task::LocalSet};

use crate::{
    crypto::{handshake, pairing},
    platform::{PlatformFuture, QlPlatform},
    runtime::{new_runtime, PeerSession, RequestConfig, RuntimeConfig, RuntimeHandle},
    wire::{handshake::HandshakeMessage, record::{Nack, RecordKind}, QlHeader, QlMessage, QlPayload},
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
        Box::pin(async move { outbound.send(message).await.map_err(|_| QlError::InvalidPayload) })
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

impl BlockingPlatform {
    fn new(seed: u8) -> (Self, Receiver<Vec<u8>>, Receiver<StatusEvent>, Arc<Semaphore>) {
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
            outbound.send(message).await.map_err(|_| QlError::InvalidPayload)
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
            let _ = handle.send_incoming(bytes).await;
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
        let (runtime_b, handle_b) = new_runtime(platform_b, RuntimeConfig::new(Duration::from_millis(200)));

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a
            .register_peer(peer_b, signing_b.clone(), encap_b.clone())
            .await
            .unwrap();
        handle_b
            .register_peer(peer_a, signing_a.clone(), encap_a.clone())
            .await
            .unwrap();

        handle_a.connect(peer_b).await.unwrap();

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

        handle_a
            .register_peer(peer_b, signing_b.clone(), encap_b.clone())
            .await
            .unwrap();

        handle_a.connect(peer_b).await.unwrap();

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
        let (runtime_b, handle_b) = new_runtime(platform_b, RuntimeConfig::new(Duration::from_millis(200)));

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a
            .register_peer(peer_b, signing_b.clone(), encap_b.clone())
            .await
            .unwrap();
        handle_b
            .register_peer(peer_a, signing_a.clone(), encap_a.clone())
            .await
            .unwrap();

        let send_a = handle_a.connect(peer_b);
        let send_b = handle_b.connect(peer_a);
        let _ = tokio::join!(send_a, send_b);

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
        let (runtime_b, handle_b) = new_runtime(platform_b, RuntimeConfig::new(Duration::from_millis(200)));

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a
            .register_peer(peer_b, wrong_public, encap_b.clone())
            .await
            .unwrap();
        handle_b
            .register_peer(peer_a, signing_a.clone(), encap_a.clone())
            .await
            .unwrap();

        handle_a.connect(peer_b).await.unwrap();

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

        let pairing_message = pairing::build_pairing_message(
            &platform_a,
            peer_b,
            &encap_b,
            MessageId::new(1),
            Duration::from_secs(1),
        )
        .expect("pairing request");
        let pairing_bytes = CBOR::from(pairing_message).to_cbor_data();

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, RuntimeConfig::new(Duration::from_millis(200)));

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a
            .register_peer(peer_b, signing_b.clone(), encap_b.clone())
            .await
            .unwrap();

        handle_b.send_incoming(pairing_bytes).await.unwrap();

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

        handle_a
            .register_peer(peer_b, signing_b.clone(), encap_b.clone())
            .await
            .unwrap();
        handle_b
            .register_peer(peer_a, signing_a.clone(), encap_a.clone())
            .await
            .unwrap();

        handle_a.connect(peer_b).await.unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let ticket = handle_a
            .send_request(
                peer_b,
                RouteId::new(7),
                CBOR::from(12u8),
                RequestConfig::default(),
            )
            .await
            .unwrap();

        handle_b
            .send_response(ticket.id, peer_a, CBOR::from(99u8), RecordKind::Response)
            .await
            .unwrap();

        let response = ticket.recv().await.unwrap();
        let value: u8 = response.try_into().unwrap();
        assert_eq!(value, 99u8);
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

        handle_a
            .register_peer(peer_b, signing_b.clone(), encap_b.clone())
            .await
            .unwrap();
        handle_b
            .register_peer(peer_a, signing_a.clone(), encap_a.clone())
            .await
            .unwrap();

        handle_a.connect(peer_b).await.unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let ticket = handle_a
            .send_request(
                peer_b,
                RouteId::new(1),
                CBOR::from(1u8),
                RequestConfig {
                    timeout: Some(Duration::from_millis(30)),
                },
            )
            .await
            .unwrap();

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

        handle_a
            .register_peer(peer_b, signing_b.clone(), encap_b.clone())
            .await
            .unwrap();
        handle_b
            .register_peer(peer_a, signing_a.clone(), encap_a.clone())
            .await
            .unwrap();

        handle_a.connect(peer_b).await.unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let ticket = handle_a
            .send_request(
                peer_b,
                RouteId::new(2),
                CBOR::from(2u8),
                RequestConfig::default(),
            )
            .await
            .unwrap();

        handle_b
            .send_response(
                ticket.id,
                peer_a,
                CBOR::from(Nack::InvalidPayload),
                RecordKind::Nack,
            )
            .await
            .unwrap();

        let ticket_id = ticket.id;
        let result = ticket.recv().await;
        assert!(matches!(
            result,
            Err(QlError::Nack {
                id,
                nack: Nack::InvalidPayload,
            }) if id == ticket_id
        ));
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

        handle_a
            .register_peer(peer_b, signing_b.clone(), encap_b.clone())
            .await
            .unwrap();

        handle_a.connect(peer_b).await.unwrap();

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

        handle_a
            .register_peer(peer_b, signing_b.clone(), encap_b.clone())
            .await
            .unwrap();

        handle_a.connect(peer_b).await.unwrap();
        await_status(&status_a, peer_b, PeerStage::Initiator).await;

        let (hello, _secret) = handshake::build_hello(&platform_b, peer_b, peer_a, &encap_a)
            .expect("hello build");
        let message = QlMessage {
            header: QlHeader {
                sender: peer_b,
                recipient: peer_a,
            },
            payload: QlPayload::Handshake(HandshakeMessage::Hello(hello)),
        };
        let bytes = CBOR::from(message).to_cbor_data();
        handle_a.send_incoming(bytes).await.unwrap();

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
