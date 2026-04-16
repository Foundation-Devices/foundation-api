use std::time::Duration;

use bytes::Bytes;

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn connect_round_trip_changes_peer_status() {
    run_local_test(async {
        let pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn opening_stream_requires_connection() {
    run_local_test(async {
        let pair = TestPair::new(default_runtime_config());
        assert!(matches!(
            pair.side(Side::A).handle.open_stream(test_route_id()).await,
            Err(NoSessionError)
        ));
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn handshake_timeout_disconnects() {
    run_local_test(async {
        let config = RuntimeConfig {
            fsm: QlFsmConfig {
                handshake_timeout: Duration::from_millis(60),
                ..default_runtime_config().fsm
            },
            ..default_runtime_config()
        };
        let (platform_a, _outbound_a, _inbound_a, status_a) = TestPlatform::new();
        let (platform_b, _outbound_b, _inbound_b, _status_b) = TestPlatform::new();
        let (identity_a, identity_b) = test_identities(&SoftwareCrypto);

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect();

        await_status(&status_a, identity_b.xid, PeerStatus::Disconnected).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn rejected_session_write_is_reissued() {
    run_local_test(async {
        let config = default_runtime_config();
        let (platform_a, outbound_a, inbound_a_tx, status_a) =
            TestPlatform::new_with_session_write_failure(1);
        let (platform_b, outbound_b, inbound_b_tx, status_b, inbound_b) =
            TestPlatform::new_with_inbound();
        let (identity_a, identity_b) = test_identities(&SoftwareCrypto);

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, inbound_b_tx);
        spawn_forwarder(outbound_b, inbound_a_tx);

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect();

        await_status(&status_a, identity_b.xid, PeerStatus::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStatus::Connected).await;

        let responder = tokio::task::spawn_local(async move {
            let stream = inbound_b.recv().await.unwrap();
            let request = read_all(stream.reader).await.unwrap();
            stream.writer.finish().await.unwrap();
            request
        });

        let mut stream = handle_a.open_stream(test_route_id()).await.unwrap();
        stream
            .writer
            .write(Bytes::from_static(b"retry"))
            .await
            .unwrap();
        stream.writer.finish().await.unwrap();
        assert_eq!(next_chunk(&mut stream.reader).await.unwrap(), None);

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), responder)
                .await
                .unwrap()
                .unwrap(),
            b"retry".to_vec()
        );

        assert_no_status_for(
            &status_a,
            identity_b.xid,
            PeerStatus::Disconnected,
            Duration::from_millis(150),
        )
        .await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn start_pairing_round_trip_connects_when_armed() {
    run_local_test(async {
        let config = default_runtime_config();
        let (platform_a, outbound_a, inbound_a_tx, status_a) = TestPlatform::new();
        let (platform_b, outbound_b, inbound_b_tx, status_b) = TestPlatform::new();
        let (identity_a, identity_b) = test_identities(&SoftwareCrypto);
        let token = pairing_token(7);

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, inbound_b_tx);
        spawn_forwarder(outbound_b, inbound_a_tx);

        handle_b.arm_pairing(token);
        handle_a.start_pairing(token);

        await_status(&status_a, identity_b.xid, PeerStatus::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStatus::Connected).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn start_pairing_does_not_connect_when_unarmed() {
    run_local_test(async {
        let config = default_runtime_config();
        let (platform_a, outbound_a, inbound_a_tx, status_a) = TestPlatform::new();
        let (platform_b, outbound_b, inbound_b_tx, _status_b) = TestPlatform::new();
        let (identity_a, identity_b) = test_identities(&SoftwareCrypto);
        let token = pairing_token(8);

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config);
        let (runtime_b, _handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, inbound_b_tx);
        spawn_forwarder(outbound_b, inbound_a_tx);

        handle_a.start_pairing(token);

        assert_no_status_for(
            &status_a,
            identity_b.xid,
            PeerStatus::Connected,
            Duration::from_millis(150),
        )
        .await;
    })
    .await;
}
