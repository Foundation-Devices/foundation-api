use super::*;

#[tokio::test(flavor = "current_thread")]
async fn handshake_initiator_connects() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) =
            new_runtime(platform_b, RuntimeConfig::new(Duration::from_millis(200)));

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_drop_heartbeat_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);

        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn handshake_timeout_disconnects() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(50));
        let (platform_a, _outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, _outbound_b, _status_b) = TestPlatform::new(2);

        let peer_b = platform_b.xid();
        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        tokio::task::spawn_local(async move { runtime_a.run().await });

        handle_a.register_peer(
            peer_b,
            platform_b.signing_public_key().clone(),
            platform_b.encapsulation_public_key().clone(),
        );

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
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) =
            new_runtime(platform_b, RuntimeConfig::new(Duration::from_millis(200)));

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);

        handle_a.connect(peer_b.xid).unwrap();
        handle_b.connect(peer_a.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Initiator).await;
        await_status(&status_b, peer_a.xid, PeerStage::Responder).await;
        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_signature_disconnects() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, _status_b) = TestPlatform::new(2);
        let (wrong_private, wrong_public) = MLDSA::MLDSA44.keypair();
        let _ = wrong_private;
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) =
            new_runtime(platform_b, RuntimeConfig::new(Duration::from_millis(200)));

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(peer_b.xid, wrong_public, peer_b.encapsulation_key.clone());
        handle_b.register_peer(
            peer_a.xid,
            peer_a.signing_key.clone(),
            peer_a.encapsulation_key.clone(),
        );

        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Disconnected).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn pairing_request_triggers_handshake() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let pairing_message = pair::build_pair_request(
            &platform_a,
            peer_b.xid,
            &peer_b.encapsulation_key,
            MessageId::new(1),
            Duration::from_secs(1),
        )
        .unwrap();
        let pairing_bytes = CBOR::from(pairing_message).to_cbor_data();

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) =
            new_runtime(platform_b, RuntimeConfig::new(Duration::from_millis(200)));

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(
            peer_b.xid,
            peer_b.signing_key.clone(),
            peer_b.encapsulation_key.clone(),
        );

        handle_b.send_incoming(pairing_bytes);

        await_status(&status_b, peer_a.xid, PeerStage::Initiator).await;
        await_status(&status_a, peer_b.xid, PeerStage::Responder).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;
        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
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
        let peer_b = platform_b.xid();

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
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        tokio::task::spawn_local(async move { runtime_a.run().await });

        handle_a.register_peer(
            peer_b.xid,
            peer_b.signing_key.clone(),
            peer_b.encapsulation_key.clone(),
        );

        handle_a.connect(peer_b.xid).unwrap();
        await_status(&status_a, peer_b.xid, PeerStage::Initiator).await;

        let (hello, _secret) = crypto_handshake::build_hello(
            &platform_b,
            peer_b.xid,
            peer_a.xid,
            &peer_a.encapsulation_key,
        )
        .unwrap();
        let message = QlRecord {
            header: QlHeader {
                sender: peer_b.xid,
                recipient: peer_a.xid,
            },
            payload: QlPayload::Handshake(HandshakeRecord::Hello(hello)),
        };
        let bytes = CBOR::from(message).to_cbor_data();
        handle_a.send_incoming(bytes);

        await_status(&status_a, peer_b.xid, PeerStage::Responder).await;
        await_status(&status_a, peer_b.xid, PeerStage::Disconnected).await;

        write_gate.add_permits(1);
        let _ = tokio::time::timeout(Duration::from_millis(100), outbound_a.recv())
            .await
            .unwrap()
            .unwrap();

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
async fn multi_peer_simultaneous_handshakes() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let (platform_c, outbound_c, status_c) = TestPlatform::new(3);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);
        let peer_c = peer_identity(&platform_c);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) =
            new_runtime(platform_b, RuntimeConfig::new(Duration::from_millis(200)));
        let (runtime_c, handle_c) =
            new_runtime(platform_c, RuntimeConfig::new(Duration::from_millis(200)));

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });
        tokio::task::spawn_local(async move { runtime_c.run().await });

        spawn_routed_forwarder(
            outbound_a,
            vec![
                (peer_b.xid, handle_b.clone()),
                (peer_c.xid, handle_c.clone()),
            ],
        );
        spawn_routed_forwarder(outbound_b, vec![(peer_a.xid, handle_a.clone())]);
        spawn_routed_forwarder(outbound_c, vec![(peer_a.xid, handle_a.clone())]);

        let _ = register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        let _ = register_peers(&handle_a, &handle_c, &peer_a, &peer_c);

        handle_a.connect(peer_b.xid).unwrap();
        handle_a.connect(peer_c.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_a, peer_c.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;
        await_status(&status_c, peer_a.xid, PeerStage::Connected).await;
    })
    .await;
}
