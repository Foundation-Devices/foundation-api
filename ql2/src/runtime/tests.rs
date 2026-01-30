use std::{
    future::Future,
    sync::atomic::{AtomicU8, Ordering},
    time::Duration,
};

use async_channel::{Receiver, Sender};
use bc_components::{
    EncapsulationPrivateKey, EncapsulationPublicKey, EncapsulationScheme, SignatureScheme,
    SigningPrivateKey, SigningPublicKey, Signer, XID,
};
use tokio::task::LocalSet;

use crate::{
    platform::{PlatformFuture, QlPlatform},
    runtime::{new_runtime, PeerSession, RuntimeConfig, RuntimeHandle},
    QlError,
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
