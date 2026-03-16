use std::time::Duration;

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn connect_round_trip_changes_peer_status() {
    run_local_test(async {
        let config = default_runtime_config();
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let identity_a = new_identity();
        let identity_b = new_identity();

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect().unwrap();

        await_status(&status_a, identity_b.xid, PeerStage::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStage::Connected).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn handshake_timeout_disconnects() {
    run_local_test(async {
        let config = RuntimeConfig {
            engine: crate::engine::EngineConfig {
                handshake_timeout: Duration::from_millis(60),
                ..default_runtime_config().engine
            },
            ..default_runtime_config()
        };
        let (platform_a, _outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, _outbound_b, _status_b) = TestPlatform::new(2);
        let identity_a = new_identity();
        let identity_b = new_identity();

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect().unwrap();

        await_status(&status_a, identity_b.xid, PeerStage::Disconnected).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn confirm_write_failure_disconnects_initiator() {
    run_local_test(async {
        let config = default_runtime_config();
        let (platform_a, outbound_a, status_a) = TestPlatform::new_with_stream_write_failure(1, 1);
        let (platform_b, outbound_b, status_b, inbound_b) = TestPlatform::new_with_inbound(2);
        let identity_a = new_identity();
        let identity_b = new_identity();

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect().unwrap();

        await_status(&status_a, identity_b.xid, PeerStage::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let second = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut second_request = second.request;
            let mut second_response = second.response;
            assert_eq!(second_request.next_chunk().await.unwrap(), None);
            second_response.write_all(b"ok").await.unwrap();
            second_response.finish().await.unwrap();
        });

        let mut first = handle_a
            .open_stream(Vec::new(), crate::runtime::StreamConfig::default())
            .await
            .unwrap();
        let _ = first.request.finish().await;
        let _ = first.response.next_chunk().await;

        assert_no_status_for(
            &status_a,
            identity_b.xid,
            PeerStage::Disconnected,
            Duration::from_millis(150),
        )
        .await;

        let mut second = handle_a
            .open_stream(Vec::new(), crate::runtime::StreamConfig::default())
            .await
            .unwrap();
        second.request.finish().await.unwrap();
        assert_eq!(second.response.next_chunk().await.unwrap(), Some(b"ok".to_vec()));
        assert_eq!(second.response.next_chunk().await.unwrap(), None);

        tokio::time::timeout(Duration::from_secs(2), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}
