use std::time::Duration;

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn connected_unpair_removes_peer_on_both_sides() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect().unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        handle_a.unpair().unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Disconnected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Disconnected).await;

        let result_a = handle_a.open_stream(Vec::new(), Default::default()).await;
        assert!(matches!(result_a, Err(QlError::NoPeerBound)));

        let result_b = handle_b.open_stream(Vec::new(), Default::default()).await;
        assert!(matches!(result_b, Err(QlError::NoPeerBound)));
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn unpair_works_without_session() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);

        await_status(&status_a, peer_b.xid, PeerStage::Disconnected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Disconnected).await;

        handle_a.unpair().unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Disconnected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Disconnected).await;

        let result_a = handle_a.open_stream(Vec::new(), Default::default()).await;
        assert!(matches!(result_a, Err(QlError::NoPeerBound)));

        let result_b = handle_b.open_stream(Vec::new(), Default::default()).await;
        assert!(matches!(result_b, Err(QlError::NoPeerBound)));
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_unpair_signature_is_ignored() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, _outbound_a, _status_a) = TestPlatform::new(1);
        let (platform_b, _outbound_b, status_b) = TestPlatform::new(2);
        let (fake_signer, _fake_outbound, _fake_status) = TestPlatform::new(3);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let forged_unpair = wire::unpair::build_unpair_record(
            &fake_signer,
            QlHeader {
                sender: peer_a.xid,
                recipient: peer_b.xid,
            },
            PacketId(777),
            now_secs().saturating_add(60),
        );
        let forged_bytes = wire::encode_record(&forged_unpair);

        let (runtime_b, handle_b) = new_runtime(platform_b, config);
        tokio::task::spawn_local(async move { runtime_b.run().await });

        handle_b.bind_peer(Peer {
            peer: peer_a.xid,
            signing_key: peer_a.signing_key.clone(),
            encapsulation_key: peer_a.encapsulation_key.clone(),
        });
        await_status(&status_b, peer_a.xid, PeerStage::Disconnected).await;

        handle_b.send_incoming(forged_bytes);

        tokio::time::sleep(Duration::from_millis(20)).await;

        let result = handle_b.open_stream(Vec::new(), Default::default()).await;
        assert!(matches!(result, Err(QlError::MissingSession)));
    })
    .await;
}
