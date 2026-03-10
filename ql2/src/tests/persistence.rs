use std::time::Duration;

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn register_peer_persists_snapshot() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, _outbound_a, _status_a, persisted_a) = PersistPlatform::new(1, None);
        let (platform_b, _outbound_b, _status_b) = TestPlatform::new(2);
        let peer_b = platform_b.xid();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        tokio::task::spawn_local(async move { runtime_a.run().await });

        handle_a.bind_peer(crate::Peer {
            peer: peer_b,
            signing_key: signing_b.clone(),
            encapsulation_key: encap_b.clone(),
        });

        let snapshot = tokio::time::timeout(Duration::from_secs(1), persisted_a.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            snapshot,
            Some(crate::Peer {
                peer: peer_b,
                signing_key: signing_b,
                encapsulation_key: encap_b,
            })
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
            Some(crate::Peer {
                peer: peer_b.xid,
                signing_key: peer_b.signing_key.clone(),
                encapsulation_key: peer_b.encapsulation_key.clone(),
            }),
        );
        let peer_a = peer_identity(&platform_a);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_b.bind_peer(crate::Peer {
            peer: peer_a.xid,
            signing_key: peer_a.signing_key.clone(),
            encapsulation_key: peer_a.encapsulation_key.clone(),
        });

        handle_a.connect().unwrap();

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

        let (platform_b, _outbound_b, _status_b, persisted_b) = PersistPlatform::new(2, None);
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
            Some(crate::Peer {
                peer: peer_a.xid,
                signing_key: peer_a.signing_key,
                encapsulation_key: peer_a.encapsulation_key,
            })
        );
    })
    .await;
}
