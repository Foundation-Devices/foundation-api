use std::{sync::atomic::Ordering, time::Duration};

use super::*;
use crate::{
    runtime::{PendingStream, StreamConfig},
    wire::stream::{
        Direction, RejectCode, ResetCode, StreamFrame, StreamFrameCredit, StreamFrameData,
    },
    RouteId,
};

#[tokio::test(flavor = "current_thread")]
async fn duplex_stream_round_trip() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(300))
            .with_packet_ack_timeout(Duration::from_millis(40))
            .with_max_payload_bytes(4)
            .with_initial_credit(4);
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            assert_eq!(stream.route_id, RouteId(11));
            assert_eq!(stream.request_head, b"req-head".to_vec());

            let mut request = stream.request;
            let mut response = stream.respond_to.accept(b"resp-head".to_vec()).unwrap();

            assert_eq!(request.next_chunk().await.unwrap(), Some(vec![1, 2]));
            response.write_all(&[9]).await.unwrap();
            assert_eq!(request.next_chunk().await.unwrap(), Some(vec![3, 4]));
            response.write_all(&[8, 7]).await.unwrap();
            assert_eq!(request.next_chunk().await.unwrap(), None);
            response.finish().await.unwrap();
        });

        let pending = handle_a
            .open_stream(
                peer_b.xid,
                RouteId(11),
                b"req-head".to_vec(),
                StreamConfig::default(),
            )
            .await
            .unwrap();
        let PendingStream {
            mut request,
            accepted,
        } = pending;
        request.write_all(&[1, 2]).await.unwrap();
        let mut accepted = accepted.await.unwrap();
        assert_eq!(accepted.response_head, b"resp-head".to_vec());
        assert_eq!(accepted.response.next_chunk().await.unwrap(), Some(vec![9]));
        request.write_all(&[3, 4]).await.unwrap();
        request.finish().await.unwrap();
        assert_eq!(
            accepted.response.next_chunk().await.unwrap(),
            Some(vec![8, 7])
        );
        assert_eq!(accepted.response.next_chunk().await.unwrap(), None);

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn duplicate_open_is_idempotent() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(400))
            .with_packet_ack_timeout(Duration::from_millis(30))
            .with_max_payload_bytes(4)
            .with_initial_credit(4);
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_drop_first_stream_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            tokio::time::sleep(Duration::from_millis(120)).await;
            let response = stream.respond_to.accept(Vec::new()).unwrap();
            let second = tokio::time::timeout(Duration::from_millis(120), inbound_b.recv()).await;
            assert!(second.is_err(), "duplicate open redispatched stream");
            response.finish().await.unwrap();
        });

        let pending = handle_a
            .open_stream(peer_b.xid, RouteId(12), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        let PendingStream { request, accepted } = pending;
        let mut accepted = accepted.await.unwrap();
        request.finish().await.unwrap();
        assert_eq!(accepted.response.next_chunk().await.unwrap(), None);

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn duplicate_accept_is_idempotent() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(400))
            .with_packet_ack_timeout(Duration::from_millis(30))
            .with_max_payload_bytes(4)
            .with_initial_credit(4);
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);
        let arm_drop = Arc::new(AtomicBool::new(false));

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_drop_first_stream_when(outbound_a, handle_b.clone(), arm_drop.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            arm_drop.store(true, Ordering::Relaxed);
            let response = stream.respond_to.accept(b"accepted".to_vec()).unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            response.finish().await.unwrap();
        });

        let pending = handle_a
            .open_stream(peer_b.xid, RouteId(13), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        let PendingStream { request, accepted } = pending;
        let mut accepted = accepted.await.unwrap();
        assert_eq!(accepted.response_head, b"accepted".to_vec());
        tokio::time::sleep(Duration::from_millis(120)).await;
        request.finish().await.unwrap();
        assert_eq!(accepted.response.next_chunk().await.unwrap(), None);

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn replayed_open_packet_is_ignored() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(300))
            .with_packet_ack_timeout(Duration::from_millis(40))
            .with_max_payload_bytes(4)
            .with_initial_credit(4);
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_duplicate_first_stream_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let second = tokio::time::timeout(Duration::from_millis(80), inbound_b.recv()).await;
            assert!(second.is_err(), "replayed open redispatched stream");
            let response = stream.respond_to.accept(Vec::new()).unwrap();
            response.finish().await.unwrap();
        });

        let pending = handle_a
            .open_stream(peer_b.xid, RouteId(14), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        let PendingStream { request, accepted } = pending;
        let mut accepted = accepted.await.unwrap();
        request.finish().await.unwrap();
        assert_eq!(accepted.response.next_chunk().await.unwrap(), None);

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn request_reset_can_keep_response_alive() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(400))
            .with_packet_ack_timeout(Duration::from_millis(40))
            .with_max_payload_bytes(16)
            .with_initial_credit(16);
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut request = stream.request;
            let mut response = stream.respond_to.accept(b"err".to_vec()).unwrap();
            assert_eq!(request.next_chunk().await.unwrap(), Some(vec![1, 2]));
            request.reset(ResetCode::InvalidData).await.unwrap();
            response.write_all(b"invalid").await.unwrap();
            response.finish().await.unwrap();
        });

        let pending = handle_a
            .open_stream(peer_b.xid, RouteId(15), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        let PendingStream {
            mut request,
            accepted,
        } = pending;
        request.write_all(&[1, 2]).await.unwrap();
        let mut accepted = accepted.await.unwrap();
        assert_eq!(accepted.response_head, b"err".to_vec());
        assert_eq!(
            accepted.response.next_chunk().await.unwrap(),
            Some(b"invalid".to_vec())
        );
        let err = request.write_all(&[3, 4]).await.unwrap_err();
        assert!(matches!(err, QlError::Cancelled));
        assert_eq!(accepted.response.next_chunk().await.unwrap(), None);

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn open_timeout_returns_error() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(120));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let pending = handle_a
            .open_stream(peer_b.xid, RouteId(16), Vec::new(), StreamConfig::default())
            .await
            .unwrap();

        let _stream = match inbound_b.recv().await.unwrap() {
            HandlerEvent::Stream(stream) => stream,
        };

        let err = pending.accepted.await.unwrap_err();
        assert!(matches!(err, QlError::Timeout));
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn reject_surfaces_stream_rejected() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(300));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            stream.respond_to.reject(RejectCode::UnknownRoute).unwrap();
        });

        let pending = handle_a
            .open_stream(peer_b.xid, RouteId(17), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        let err = pending.accepted.await.unwrap_err();
        assert!(matches!(
            err,
            QlError::StreamRejected {
                code: RejectCode::UnknownRoute,
                ..
            }
        ));
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_responder_rejects_unhandled() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(300));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut request = stream.request;
            drop(stream.respond_to);
            assert!(matches!(
                request.next_chunk().await,
                Ok(None) | Err(QlError::Cancelled)
            ));
        });

        let PendingStream { request, accepted } = handle_a
            .open_stream(peer_b.xid, RouteId(18), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        request.finish().await.unwrap();

        let err = tokio::time::timeout(Duration::from_secs(1), accepted)
            .await
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            err,
            QlError::StreamRejected {
                code: RejectCode::Unhandled,
                ..
            }
        ));

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn request_larger_than_ring_buffer_streams_with_backpressure() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(400))
            .with_packet_ack_timeout(Duration::from_millis(30))
            .with_max_payload_bytes(4)
            .with_pipe_size_bytes(4)
            .with_initial_credit(4);
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);
        let payload: Vec<u8> = (0..24).collect();
        let (done_tx, done_rx) = async_channel::bounded(1);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut request = stream.request;
            let response = stream.respond_to.accept(Vec::new()).unwrap();
            let mut received = Vec::new();
            while let Some(chunk) = request.next_chunk().await.unwrap() {
                received.extend_from_slice(&chunk);
            }
            done_tx.send(received).await.unwrap();
            response.finish().await.unwrap();
        });

        let PendingStream {
            mut request,
            accepted,
        } = handle_a
            .open_stream(peer_b.xid, RouteId(19), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        request.write_all(&payload).await.unwrap();
        request.finish().await.unwrap();

        let mut accepted = tokio::time::timeout(Duration::from_secs(1), accepted)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepted.response.next_chunk().await.unwrap(), None);

        let received = tokio::time::timeout(Duration::from_secs(1), done_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, payload);

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn response_larger_than_ring_buffer_streams_with_backpressure() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(400))
            .with_packet_ack_timeout(Duration::from_millis(30))
            .with_max_payload_bytes(4)
            .with_pipe_size_bytes(4)
            .with_initial_credit(4);
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);
        let payload: Vec<u8> = (50..74).collect();
        let expected = payload.clone();

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut request = stream.request;
            let mut response = stream.respond_to.accept(Vec::new()).unwrap();
            assert_eq!(request.next_chunk().await.unwrap(), None);
            response.write_all(&payload).await.unwrap();
            response.finish().await.unwrap();
        });

        let PendingStream { request, accepted } = handle_a
            .open_stream(peer_b.xid, RouteId(20), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        request.finish().await.unwrap();

        let mut accepted = tokio::time::timeout(Duration::from_secs(1), accepted)
            .await
            .unwrap()
            .unwrap();
        let mut received = Vec::new();
        while let Some(chunk) = accepted.response.next_chunk().await.unwrap() {
            received.extend_from_slice(&chunk);
        }
        assert_eq!(received, expected);

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_pending_accept_cancels_response_side() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(400))
            .with_packet_ack_timeout(Duration::from_millis(30))
            .with_max_payload_bytes(4)
            .with_pipe_size_bytes(4)
            .with_initial_credit(4);
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut request = stream.request;
            let mut response = stream.respond_to.accept(Vec::new()).unwrap();
            assert_eq!(request.next_chunk().await.unwrap(), None);
            let err = response
                .write_all(&[1, 2, 3, 4, 5, 6, 7, 8])
                .await
                .unwrap_err();
            assert!(matches!(err, QlError::Cancelled));
        });

        let PendingStream { request, accepted } = handle_a
            .open_stream(peer_b.xid, RouteId(21), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        drop(accepted);
        request.finish().await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_request_writer_sends_cancel() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(300))
            .with_packet_ack_timeout(Duration::from_millis(30))
            .with_max_payload_bytes(4)
            .with_initial_credit(4);
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut request = stream.request;
            let response = stream.respond_to.accept(Vec::new()).unwrap();
            assert_eq!(request.next_chunk().await.unwrap(), Some(vec![1, 2, 3, 4]));
            let err = request.next_chunk().await.unwrap_err();
            assert!(matches!(
                err,
                QlError::StreamReset {
                    dir: Direction::Request,
                    code: ResetCode::Cancelled,
                    ..
                }
            ));
            response.finish().await.unwrap();
        });

        let PendingStream {
            mut request,
            accepted,
        } = handle_a
            .open_stream(peer_b.xid, RouteId(22), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        request.write_all(&[1, 2, 3, 4]).await.unwrap();
        let mut accepted = accepted.await.unwrap();
        drop(request);
        assert_eq!(accepted.response.next_chunk().await.unwrap(), None);

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_response_writer_sends_cancel() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(300))
            .with_packet_ack_timeout(Duration::from_millis(30))
            .with_max_payload_bytes(4)
            .with_initial_credit(4);
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let mut stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut response = stream.respond_to.accept(Vec::new()).unwrap();
            assert_eq!(stream.request.next_chunk().await.unwrap(), None);
            response.write_all(&[9, 8, 7, 6]).await.unwrap();
            drop(response);
        });

        let PendingStream { request, accepted } = handle_a
            .open_stream(peer_b.xid, RouteId(23), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        request.finish().await.unwrap();
        let mut accepted = accepted.await.unwrap();
        assert_eq!(
            accepted.response.next_chunk().await.unwrap(),
            Some(vec![9, 8, 7, 6])
        );
        let err = accepted.response.next_chunk().await.unwrap_err();
        assert!(matches!(
            err,
            QlError::StreamReset {
                dir: Direction::Response,
                code: ResetCode::Cancelled,
                ..
            }
        ));

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_request_reader_sends_cancel() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(300))
            .with_packet_ack_timeout(Duration::from_millis(30))
            .with_max_payload_bytes(4)
            .with_initial_credit(4);
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut request = stream.request;
            let response = stream.respond_to.accept(Vec::new()).unwrap();
            assert_eq!(request.next_chunk().await.unwrap(), Some(vec![1, 2, 3, 4]));
            drop(request);
            response.finish().await.unwrap();
        });

        let PendingStream {
            mut request,
            accepted,
        } = handle_a
            .open_stream(peer_b.xid, RouteId(24), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        request.write_all(&[1, 2, 3, 4]).await.unwrap();
        let mut accepted = accepted.await.unwrap();
        // ensure that the runtime can process the drop
        tokio::time::sleep(Duration::from_millis(20)).await;
        let err = request.write_all(&[5, 6, 7, 8]).await.unwrap_err();
        assert!(matches!(err, QlError::Cancelled));
        assert_eq!(accepted.response.next_chunk().await.unwrap(), None);

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_response_reader_sends_cancel() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(300))
            .with_packet_ack_timeout(Duration::from_millis(30))
            .with_max_payload_bytes(4)
            .with_pipe_size_bytes(4)
            .with_initial_credit(4);
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);
        let (go_tx, go_rx) = async_channel::bounded(1);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let mut stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut response = stream.respond_to.accept(Vec::new()).unwrap();
            assert_eq!(stream.request.next_chunk().await.unwrap(), None);
            go_rx.recv().await.unwrap();
            let err = response
                .write_all(&[1, 2, 3, 4, 5, 6, 7, 8])
                .await
                .unwrap_err();
            assert!(matches!(err, QlError::Cancelled));
        });

        let PendingStream { request, accepted } = handle_a
            .open_stream(peer_b.xid, RouteId(25), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        request.finish().await.unwrap();
        let accepted = accepted.await.unwrap();
        drop(accepted.response);
        go_tx.send(()).await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn empty_request_finishes_cleanly() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(300));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut request = stream.request;
            let mut response = stream.respond_to.accept(Vec::new()).unwrap();
            assert_eq!(request.next_chunk().await.unwrap(), None);
            response.write_all(b"ok").await.unwrap();
            response.finish().await.unwrap();
        });

        let PendingStream { request, accepted } = handle_a
            .open_stream(peer_b.xid, RouteId(26), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        request.finish().await.unwrap();
        let mut accepted = accepted.await.unwrap();
        assert_eq!(
            accepted.response.next_chunk().await.unwrap(),
            Some(b"ok".to_vec())
        );
        assert_eq!(accepted.response.next_chunk().await.unwrap(), None);

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn empty_response_finishes_cleanly() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(300));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut request = stream.request;
            let response = stream.respond_to.accept(Vec::new()).unwrap();
            assert_eq!(request.next_chunk().await.unwrap(), Some(vec![1]));
            assert_eq!(request.next_chunk().await.unwrap(), None);
            response.finish().await.unwrap();
        });

        let PendingStream {
            mut request,
            accepted,
        } = handle_a
            .open_stream(peer_b.xid, RouteId(27), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        request.write_all(&[1]).await.unwrap();
        request.finish().await.unwrap();
        let mut accepted = accepted.await.unwrap();
        assert_eq!(accepted.response.next_chunk().await.unwrap(), None);

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn stream_survives_every_third_packet_drop() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(500))
            .with_packet_ack_timeout(Duration::from_millis(20))
            .with_stream_retry_limit(12)
            .with_max_payload_bytes(4)
            .with_pipe_size_bytes(4)
            .with_initial_credit(4);
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);
        let request_payload: Vec<u8> = (0..32).collect();
        let response_payload: Vec<u8> = (100..132).collect();
        let expected_response = response_payload.clone();
        let (done_tx, done_rx) = async_channel::bounded(1);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_drop_every_nth_stream_forwarder(outbound_a, handle_b.clone(), 3);
        spawn_drop_every_nth_stream_forwarder(outbound_b, handle_a.clone(), 3);

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut request = stream.request;
            let mut response = stream.respond_to.accept(Vec::new()).unwrap();
            let mut received = Vec::new();
            while let Some(chunk) = request.next_chunk().await.unwrap() {
                received.extend_from_slice(&chunk);
            }
            response.write_all(&response_payload).await.unwrap();
            response.finish().await.unwrap();
            done_tx.send(received).await.unwrap();
        });

        let PendingStream {
            mut request,
            accepted,
        } = handle_a
            .open_stream(peer_b.xid, RouteId(28), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        request.write_all(&request_payload).await.unwrap();
        request.finish().await.unwrap();

        let mut accepted = tokio::time::timeout(Duration::from_secs(3), accepted)
            .await
            .unwrap()
            .unwrap();
        let mut received_response = Vec::new();
        while let Some(chunk) = accepted.response.next_chunk().await.unwrap() {
            received_response.extend_from_slice(&chunk);
        }
        assert_eq!(received_response, expected_response);

        let received_request = tokio::time::timeout(Duration::from_secs(3), done_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received_request, request_payload);

        tokio::time::timeout(Duration::from_secs(3), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn response_data_before_accept_is_protocol_error() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(400))
            .with_packet_ack_timeout(Duration::from_millis(30))
            .with_stream_retry_limit(8)
            .with_max_payload_bytes(4)
            .with_initial_credit(4);
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);
        let key_material = session_key_material(&platform_a, &platform_b);
        let trace = Arc::new(Mutex::new(SessionTrace::default()));

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_stream_mutating_forwarder(
            outbound_a,
            handle_b.clone(),
            key_material.clone(),
            trace.clone(),
            |_header, _body| false,
        );
        spawn_stream_mutating_forwarder(outbound_b, handle_a.clone(), key_material, trace, {
            let mut mutated = false;
            move |_header, body| {
                if mutated {
                    return false;
                }
                if let Some(StreamFrame::Accept(frame)) = body.frame.take() {
                    mutated = true;
                    body.frame = Some(StreamFrame::Data(StreamFrameData {
                        stream_id: frame.stream_id,
                        dir: Direction::Response,
                        offset: 0,
                        bytes: vec![9],
                    }));
                    true
                } else {
                    false
                }
            }
        });

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut response = stream.respond_to.accept(Vec::new()).unwrap();
            response.write_all(&[9]).await.unwrap();
            let _ = response.finish().await;
        });

        let PendingStream { request, accepted } = handle_a
            .open_stream(peer_b.xid, RouteId(34), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        request.finish().await.unwrap();
        let err = tokio::time::timeout(Duration::from_secs(1), accepted)
            .await
            .unwrap()
            .unwrap_err();
        assert!(matches!(err, QlError::StreamProtocol { .. }));

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn data_offset_gap_is_protocol_error() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(400))
            .with_packet_ack_timeout(Duration::from_millis(30))
            .with_stream_retry_limit(8)
            .with_max_payload_bytes(4)
            .with_initial_credit(4);
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);
        let key_material = session_key_material(&platform_a, &platform_b);
        let trace = Arc::new(Mutex::new(SessionTrace::default()));

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_stream_mutating_forwarder(
            outbound_a,
            handle_b.clone(),
            key_material.clone(),
            trace.clone(),
            {
                let mut mutated = false;
                move |_header, body| {
                    if mutated {
                        return false;
                    }
                    if let Some(StreamFrame::Data(frame)) = body.frame.as_mut() {
                        mutated = true;
                        frame.offset = 2;
                        true
                    } else {
                        false
                    }
                }
            },
        );
        spawn_stream_mutating_forwarder(
            outbound_b,
            handle_a.clone(),
            key_material,
            trace,
            |_header, _body| false,
        );

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut request = stream.request;
            let response = stream.respond_to.accept(Vec::new()).unwrap();
            let err = request.next_chunk().await.unwrap_err();
            assert!(matches!(err, QlError::StreamProtocol { .. }));
            let _ = response.finish().await;
        });

        let PendingStream {
            mut request,
            accepted,
        } = handle_a
            .open_stream(peer_b.xid, RouteId(35), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        let _accepted = accepted.await.unwrap();
        request.write_all(&[1, 2, 3, 4]).await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn data_beyond_credit_is_protocol_error() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(400))
            .with_packet_ack_timeout(Duration::from_millis(30))
            .with_stream_retry_limit(8)
            .with_max_payload_bytes(4)
            .with_initial_credit(4);
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);
        let key_material = session_key_material(&platform_a, &platform_b);
        let trace = Arc::new(Mutex::new(SessionTrace::default()));

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_stream_mutating_forwarder(
            outbound_a,
            handle_b.clone(),
            key_material.clone(),
            trace.clone(),
            {
                let mut mutated = false;
                move |_header, body| {
                    if mutated {
                        return false;
                    }
                    if let Some(StreamFrame::Data(frame)) = body.frame.as_mut() {
                        mutated = true;
                        frame.offset = 4;
                        true
                    } else {
                        false
                    }
                }
            },
        );
        spawn_stream_mutating_forwarder(
            outbound_b,
            handle_a.clone(),
            key_material,
            trace,
            |_header, _body| false,
        );

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut request = stream.request;
            let response = stream.respond_to.accept(Vec::new()).unwrap();
            let err = request.next_chunk().await.unwrap_err();
            assert!(matches!(err, QlError::StreamProtocol { .. }));
            let _ = response.finish().await;
        });

        let PendingStream {
            mut request,
            accepted,
        } = handle_a
            .open_stream(peer_b.xid, RouteId(36), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        let _accepted = accepted.await.unwrap();
        request.write_all(&[1, 2, 3, 4]).await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn credit_regression_is_protocol_error() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(400))
            .with_packet_ack_timeout(Duration::from_millis(30))
            .with_stream_retry_limit(8)
            .with_max_payload_bytes(4)
            .with_initial_credit(4);
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);
        let key_material = session_key_material(&platform_a, &platform_b);
        let trace = Arc::new(Mutex::new(SessionTrace::default()));

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_stream_mutating_forwarder(
            outbound_a,
            handle_b.clone(),
            key_material.clone(),
            trace.clone(),
            |_header, _body| false,
        );
        spawn_stream_mutating_forwarder(outbound_b, handle_a.clone(), key_material, trace, {
            let mut mutated = false;
            move |_header, body| {
                if mutated {
                    return false;
                }
                if let Some(StreamFrame::Credit(StreamFrameCredit {
                    dir: Direction::Request,
                    recv_offset,
                    max_offset,
                    ..
                })) = body.frame.as_mut()
                {
                    mutated = true;
                    *recv_offset = 99;
                    *max_offset = 99;
                    true
                } else {
                    false
                }
            }
        });

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut request = stream.request;
            let response = stream.respond_to.accept(Vec::new()).unwrap();
            assert_eq!(request.next_chunk().await.unwrap(), Some(vec![1, 2, 3, 4]));
            let err = request.next_chunk().await.unwrap_err();
            assert!(matches!(
                err,
                QlError::StreamReset {
                    code: ResetCode::Protocol,
                    dir: Direction::Request,
                    ..
                }
            ));
            let _ = response.finish().await;
        });

        let PendingStream {
            mut request,
            accepted,
        } = handle_a
            .open_stream(peer_b.xid, RouteId(37), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        let mut accepted = accepted.await.unwrap();
        request.write_all(&[1, 2, 3, 4]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let err = request.write_all(&[5, 6, 7, 8]).await.unwrap_err();
        assert!(matches!(err, QlError::Cancelled));
        assert!(matches!(
            accepted.response.next_chunk().await,
            Ok(None) | Err(_)
        ));

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn disconnect_during_active_stream_aborts_both_halves() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_open_timeout(Duration::from_millis(400))
            .with_packet_ack_timeout(Duration::from_millis(30));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let handle_b_for_disconnect = handle_b.clone();
        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut request = stream.request;
            let _response = stream.respond_to.accept(Vec::new()).unwrap();
            assert_eq!(request.next_chunk().await.unwrap(), Some(vec![1, 2, 3, 4]));
            let request_outcome = request.next_chunk().await;
            assert!(matches!(
                request_outcome,
                Ok(None)
                    | Err(QlError::Cancelled)
                    | Err(QlError::SendFailed)
                    | Err(QlError::StreamReset { .. })
                    | Err(QlError::StreamProtocol { .. })
            ));
            handle_b_for_disconnect.unpair(peer_a.xid).unwrap();
        });

        let PendingStream {
            mut request,
            accepted,
        } = handle_a
            .open_stream(peer_b.xid, RouteId(38), Vec::new(), StreamConfig::default())
            .await
            .unwrap();
        request.write_all(&[1, 2, 3, 4]).await.unwrap();
        let mut accepted = accepted.await.unwrap();
        handle_a.unpair(peer_b.xid).unwrap();
        await_status(&status_a, peer_b.xid, PeerStage::Disconnected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Disconnected).await;
        tokio::time::sleep(Duration::from_millis(20)).await;

        let write_err = request.write_all(&[5, 6, 7, 8]).await.unwrap_err();
        assert!(matches!(write_err, QlError::Cancelled));
        assert!(matches!(
            accepted.response.next_chunk().await,
            Ok(None) | Err(_)
        ));

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}
