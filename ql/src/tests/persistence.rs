use std::sync::atomic::{AtomicU8, Ordering};

use async_channel::{Receiver, Sender};
use bc_components::{
    MLDSAPrivateKey, MLDSAPublicKey, MLKEMPrivateKey, MLKEMPublicKey, MLDSA, MLKEM, XID,
};

use super::*;

struct PersistPlatform {
    signing_private: MLDSAPrivateKey,
    signing_public: MLDSAPublicKey,
    encapsulation_private: MLKEMPrivateKey,
    encapsulation_public: MLKEMPublicKey,
    outbound: Sender<Vec<u8>>,
    status: Sender<StatusEvent>,
    persisted: Sender<Vec<crate::Peer>>,
    loaded_peers: Vec<crate::Peer>,
    nonce_seed: u8,
    nonce_counter: AtomicU8,
}

impl PersistPlatform {
    fn new(
        seed: u8,
        loaded_peers: Vec<crate::Peer>,
    ) -> (
        Self,
        Receiver<Vec<u8>>,
        Receiver<StatusEvent>,
        Receiver<Vec<crate::Peer>>,
    ) {
        let (signing_private, signing_public) = MLDSA::MLDSA44.keypair();
        let (encapsulation_private, encapsulation_public) = MLKEM::MLKEM512.keypair();
        let (outbound, outbound_rx) = async_channel::unbounded();
        let (status, status_rx) = async_channel::unbounded();
        let (persisted, persisted_rx) = async_channel::unbounded();
        (
            Self {
                signing_private,
                signing_public,
                encapsulation_private,
                encapsulation_public,
                outbound,
                status,
                persisted,
                loaded_peers,
                nonce_seed: seed,
                nonce_counter: AtomicU8::new(0),
            },
            outbound_rx,
            status_rx,
            persisted_rx,
        )
    }
}

impl QlPlatform for PersistPlatform {
    fn signing_private_key(&self) -> &MLDSAPrivateKey {
        &self.signing_private
    }

    fn signing_public_key(&self) -> &MLDSAPublicKey {
        &self.signing_public
    }

    fn encapsulation_private_key(&self) -> &MLKEMPrivateKey {
        &self.encapsulation_private
    }

    fn encapsulation_public_key(&self) -> &MLKEMPublicKey {
        &self.encapsulation_public
    }

    fn fill_random_bytes(&self, data: &mut [u8]) {
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

    fn load_peers(&self) -> PlatformFuture<'_, Vec<crate::Peer>> {
        let peers = self.loaded_peers.clone();
        Box::pin(async move { peers })
    }

    fn persist_peers(&self, peers: Vec<crate::Peer>) {
        let _ = self.persisted.try_send(peers);
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

    fn handle_inbound(&self, _event: HandlerEvent) {}
}

#[tokio::test(flavor = "current_thread")]
async fn register_peer_persists_snapshot() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, _outbound_a, _status_a, persisted_a) = PersistPlatform::new(1, Vec::new());
        let (platform_b, _outbound_b, _status_b) = TestPlatform::new(2);
        let peer_b = platform_b.xid();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        tokio::task::spawn_local(async move { runtime_a.run().await });

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());

        let snapshot = tokio::time::timeout(Duration::from_secs(1), persisted_a.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            snapshot,
            vec![crate::Peer {
                peer: peer_b,
                signing_key: signing_b,
                encapsulation_key: encap_b,
            }]
        );
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn loaded_peers_can_connect_without_register() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let peer_b = peer_identity(&platform_b);

        let (platform_a, outbound_a, status_a, _persisted_a) = PersistPlatform::new(
            1,
            vec![crate::Peer {
                peer: peer_b.xid,
                signing_key: peer_b.signing_key.clone(),
                encapsulation_key: peer_b.encapsulation_key.clone(),
            }],
        );
        let peer_a = peer_identity(&platform_a);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) =
            new_runtime(platform_b, RuntimeConfig::new(Duration::from_millis(200)));

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_b.register_peer(
            peer_a.xid,
            peer_a.signing_key.clone(),
            peer_a.encapsulation_key.clone(),
        );

        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn pairing_persists_snapshot() {
    run_local_test(async {
        let (platform_a, _outbound_a, _status_a) = TestPlatform::new(1);
        let peer_a = peer_identity(&platform_a);

        let (platform_b, _outbound_b, _status_b, persisted_b) = PersistPlatform::new(2, Vec::new());
        let peer_b = peer_identity(&platform_b);

        let pairing_message = pair::build_pair_request(
            &platform_a,
            peer_b.xid,
            &peer_b.encapsulation_key,
            MessageId(1),
            Duration::from_secs(1),
        )
        .unwrap();
        let pairing_bytes = CBOR::from(pairing_message).to_cbor_data();

        let (runtime_b, handle_b) =
            new_runtime(platform_b, RuntimeConfig::new(Duration::from_millis(200)));
        tokio::task::spawn_local(async move { runtime_b.run().await });

        handle_b.send_incoming(pairing_bytes);

        let snapshot = tokio::time::timeout(Duration::from_secs(1), persisted_b.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            snapshot,
            vec![crate::Peer {
                peer: peer_a.xid,
                signing_key: peer_a.signing_key,
                encapsulation_key: peer_a.encapsulation_key,
            }]
        );
    })
    .await;
}
