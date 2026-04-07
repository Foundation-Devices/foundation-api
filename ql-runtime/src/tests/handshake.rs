use std::time::Duration;

use bytes::Bytes;

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn connect_round_trip_changes_peer_status() {
    run_local_test(async {
        let config = default_runtime_config();
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let identity_a = new_identity(11);
        let identity_b = new_identity(73);

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect();

        await_status(&status_a, identity_b.xid, PeerStatus::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStatus::Connected).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn opening_stream_requires_connection() {
    run_local_test(async {
        let config = default_runtime_config();
        let (platform_a, _outbound_a, _status_a) = TestPlatform::new(1);
        let (platform_b, _outbound_b, _status_b, _inbound_b) = TestPlatform::new_with_inbound(2);
        let identity_a = new_identity(11);
        let identity_b = new_identity(73);

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        assert!(matches!(
            handle_a.open_stream().await,
            Err(QlError::NoSession)
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
        let (platform_a, _outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, _outbound_b, _status_b) = TestPlatform::new(2);
        let identity_a = new_identity(11);
        let identity_b = new_identity(73);

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
        let (platform_a, outbound_a, status_a) = TestPlatform::new_with_session_write_failure(1, 1);
        let (platform_b, outbound_b, status_b, inbound_b) = TestPlatform::new_with_inbound(2);
        let identity_a = new_identity(11);
        let identity_b = new_identity(73);

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect();

        await_status(&status_a, identity_b.xid, PeerStatus::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStatus::Connected).await;

        let responder = tokio::task::spawn_local(async move {
            let stream = inbound_b.recv().await.unwrap();
            let request = read_all(stream.reader).await.unwrap();
            stream.writer.finish();
            request
        });

        let mut stream = handle_a.open_stream().await.unwrap();
        stream
            .writer
            .write(Bytes::from_static(b"retry"))
            .await
            .unwrap();
        stream.writer.finish();
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
