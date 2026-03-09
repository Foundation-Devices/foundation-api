use std::{sync::atomic::Ordering, time::Duration};

use super::*;
use crate::{
    runtime::{PendingStream, StreamConfig},
    wire::stream::{RejectCode, ResetCode},
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
                true,
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
            .open_stream(
                peer_b.xid,
                RouteId(12),
                Vec::new(),
                true,
                StreamConfig::default(),
            )
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
            .open_stream(
                peer_b.xid,
                RouteId(13),
                Vec::new(),
                true,
                StreamConfig::default(),
            )
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
            .open_stream(
                peer_b.xid,
                RouteId(14),
                Vec::new(),
                true,
                StreamConfig::default(),
            )
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
            .open_stream(
                peer_b.xid,
                RouteId(15),
                Vec::new(),
                true,
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
            .open_stream(
                peer_b.xid,
                RouteId(16),
                Vec::new(),
                true,
                StreamConfig::default(),
            )
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
            .open_stream(
                peer_b.xid,
                RouteId(17),
                Vec::new(),
                true,
                StreamConfig::default(),
            )
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
