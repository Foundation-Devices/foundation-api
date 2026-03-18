use std::time::Duration;

use super::*;
use crate::{CloseCode, CloseTarget};

#[tokio::test(flavor = "current_thread")]
async fn open_stream_duplex_happy_path() {
    run_local_test(async {
        let config = default_runtime_config();
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
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
        handle_a.connect().unwrap();

        await_status(&status_a, identity_b.xid, PeerStage::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStage::Connected).await;

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();

            let mut request = inbound.request;
            let mut response = inbound.response;

            assert_eq!(request.next_chunk().await.unwrap(), Some(vec![1, 2]));
            response.write_all(&[9]).await.unwrap();
            assert_eq!(request.next_chunk().await.unwrap(), Some(vec![3, 4]));
            response.write_all(&[8, 7]).await.unwrap();
            assert_eq!(request.next_chunk().await.unwrap(), None);
            response.finish().await.unwrap();
        });

        let mut stream = handle_a.open_stream().await.unwrap();
        stream.request.write_all(&[1, 2]).await.unwrap();
        assert_eq!(stream.response.next_chunk().await.unwrap(), Some(vec![9]));
        stream.request.write_all(&[3, 4]).await.unwrap();
        stream.request.finish().await.unwrap();
        assert_eq!(
            stream.response.next_chunk().await.unwrap(),
            Some(vec![8, 7])
        );
        assert_eq!(stream.response.next_chunk().await.unwrap(), None);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn stream_backpressure_with_small_runtime_buffer() {
    run_local_test(async {
        let config = RuntimeConfig {
            stream_send_buffer_bytes: 4,
            ..default_runtime_config()
        };
        let payload: Vec<u8> = (0..40).collect();

        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = TestPlatform::new_with_inbound(2);
        let identity_a = new_identity(11);
        let identity_b = new_identity(73);
        let (done_tx, done_rx) = async_channel::bounded(1);

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

        let responder = tokio::task::spawn_local(async move {
            let stream = inbound_b.recv().await.unwrap();
            let request_data = read_all(stream.request).await.unwrap();
            stream.response.finish().await.unwrap();
            done_tx.send(request_data).await.unwrap();
        });

        let mut stream = handle_a.open_stream().await.unwrap();
        stream.request.write_all(&payload).await.unwrap();
        stream.request.finish().await.unwrap();
        assert_eq!(stream.response.next_chunk().await.unwrap(), None);

        let received = tokio::time::timeout(Duration::from_secs(2), done_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, payload);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_responder_closes_initiator_response() {
    run_local_test(async {
        let config = default_runtime_config();
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
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
        handle_a.connect().unwrap();

        await_status(&status_a, identity_b.xid, PeerStage::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStage::Connected).await;

        let responder = tokio::task::spawn_local(async move {
            let stream = inbound_b.recv().await.unwrap();
            drop(stream.response);
        });

        let mut stream = handle_a.open_stream().await.unwrap();
        stream.request.finish().await.unwrap();

        let err = stream.response.next_chunk().await.unwrap_err();
        assert!(matches!(
            err,
            QlError::StreamClosed {
                target: CloseTarget::Response,
                code: CloseCode::CANCELLED,
                payload,
            } if payload.is_empty()
        ));

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_inbound_reader_cancels_remote_writer() {
    run_local_test(async {
        let config = RuntimeConfig {
            stream_send_buffer_bytes: 4,
            ..default_runtime_config()
        };
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = TestPlatform::new_with_inbound(2);
        let identity_a = new_identity(11);
        let identity_b = new_identity(73);
        let (go_tx, go_rx) = async_channel::bounded(1);

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

        let responder = tokio::task::spawn_local(async move {
            let stream = inbound_b.recv().await.unwrap();
            let mut request = stream.request;
            let mut response = stream.response;
            assert_eq!(request.next_chunk().await.unwrap(), None);
            response.write_all(&[1, 2, 3, 4]).await.unwrap();
            go_rx.recv().await.unwrap();
            let err = response.write_all(&[5; 64]).await.unwrap_err();
            assert!(matches!(err, QlError::Cancelled));
        });

        let mut stream = handle_a.open_stream().await.unwrap();
        stream.request.finish().await.unwrap();
        assert_eq!(
            stream.response.next_chunk().await.unwrap(),
            Some(vec![1, 2, 3, 4])
        );
        drop(stream.response);
        go_tx.send(()).await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn max_concurrent_message_writes_is_respected() {
    run_local_test(async {
        let stats = WriteStats::new();
        let config = RuntimeConfig {
            max_concurrent_message_writes: 2,
            ..default_runtime_config()
        };
        let (platform_a, outbound_a, status_a) =
            TestPlatform::new_with_delayed_writes(1, Duration::from_millis(40), stats.clone());
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
        handle_a.connect().unwrap();

        await_status(&status_a, identity_b.xid, PeerStage::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStage::Connected).await;

        let responder = tokio::task::spawn_local(async move {
            for _ in 0..4 {
                let stream = inbound_b.recv().await.unwrap();
                let _ = read_all(stream.request).await;
                let _ = stream.response.finish().await;
            }
        });

        let mut tasks = Vec::new();
        for i in 0..4u8 {
            let handle = handle_a.clone();
            tasks.push(tokio::task::spawn_local(async move {
                let mut stream = handle.open_stream().await.unwrap();
                stream.request.write_all(&[i; 8]).await.unwrap();
                stream.request.finish().await.unwrap();
                assert_eq!(stream.response.next_chunk().await.unwrap(), None);
            }));
        }

        for task in tasks {
            tokio::time::timeout(Duration::from_secs(4), task)
                .await
                .unwrap()
                .unwrap();
        }

        tokio::time::timeout(Duration::from_secs(4), responder)
            .await
            .unwrap()
            .unwrap();

        assert!(
            stats.max_active() <= 2,
            "max active writes exceeded: {}",
            stats.max_active()
        );
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn stream_round_trip_survives_encrypted_packet_drops() {
    run_local_test(async {
        let config = RuntimeConfig {
            fsm: QlFsmConfig {
                session_retransmit_timeout: Duration::from_millis(20),
                ..default_runtime_config().fsm
            },
            stream_send_buffer_bytes: 4,
            ..default_runtime_config()
        };
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = TestPlatform::new_with_inbound(2);
        let identity_a = new_identity(11);
        let identity_b = new_identity(73);

        let request_payload: Vec<u8> = (0..32).collect();
        let response_payload: Vec<u8> = (100..132).collect();
        let expected_response = response_payload.clone();

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_drop_every_nth_encrypted_forwarder(outbound_a, handle_b.clone(), 3);
        spawn_drop_every_nth_encrypted_forwarder(outbound_b, handle_a.clone(), 3);

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect().unwrap();

        await_status(&status_a, identity_b.xid, PeerStage::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStage::Connected).await;

        let responder = tokio::task::spawn_local(async move {
            let stream = inbound_b.recv().await.unwrap();
            let received_request = read_all(stream.request).await.unwrap();
            let mut response = stream.response;
            response.write_all(&response_payload).await.unwrap();
            response.finish().await.unwrap();
            received_request
        });

        let mut stream = handle_a.open_stream().await.unwrap();
        stream.request.write_all(&request_payload).await.unwrap();
        stream.request.finish().await.unwrap();

        let mut received_response = Vec::new();
        while let Some(chunk) = stream.response.next_chunk().await.unwrap() {
            received_response.extend_from_slice(&chunk);
        }
        assert_eq!(received_response, expected_response);

        let received_request = tokio::time::timeout(Duration::from_secs(4), responder)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received_request, request_payload);
    })
    .await;
}
