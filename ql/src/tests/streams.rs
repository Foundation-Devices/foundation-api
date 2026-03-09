use super::*;

#[tokio::test(flavor = "current_thread")]
async fn request_stream_round_trip() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_request_timeout(Duration::from_millis(200));
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
            if let Ok(HandlerEvent::Request(request)) = inbound_b.recv().await {
                let mut stream = request.respond_to.respond_stream(7u8).unwrap();
                stream.write_next(vec![1, 2, 3]).await.unwrap();
                stream.write_next(vec![4, 5]).await.unwrap();
                stream.finish().await.unwrap();
            }
        });

        let mut response = handle_a
            .send_request_stream_raw(
                peer_b.xid,
                RouteId(201),
                CBOR::from(1u8),
                RequestConfig::default(),
            )
            .recv()
            .await
            .unwrap();

        assert_eq!(response.meta, CBOR::from(7u8));
        assert_eq!(
            response.body.next_chunk().await.unwrap(),
            Some(vec![1, 2, 3])
        );
        assert_eq!(response.body.next_chunk().await.unwrap(), Some(vec![4, 5]));
        assert_eq!(response.body.next_chunk().await.unwrap(), None);

        let _ = responder_task.await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_inbound_stream_cancels_sender() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_request_timeout(Duration::from_millis(200));
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
            if let Ok(HandlerEvent::Request(request)) = inbound_b.recv().await {
                let mut stream = request.respond_to.respond_stream(1u8).unwrap();
                stream.write_next(vec![9]).await.unwrap();
                stream.finish().await
            } else {
                Err(QlError::Cancelled)
            }
        });

        let mut response = handle_a
            .send_request_stream_raw(
                peer_b.xid,
                RouteId(202),
                CBOR::from(2u8),
                RequestConfig::default(),
            )
            .recv()
            .await
            .unwrap();

        assert_eq!(response.body.next_chunk().await.unwrap(), Some(vec![9]));
        drop(response);

        let result = tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn sender_cancel_surfaces_error_on_receiver() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_request_timeout(Duration::from_millis(200));
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
            if let Ok(HandlerEvent::Request(request)) = inbound_b.recv().await {
                let mut stream = request.respond_to.respond_stream(1u8).unwrap();
                stream.write_next(vec![7]).await.unwrap();
                stream.cancel().await.unwrap();
            }
        });

        let mut response = handle_a
            .send_request_stream_raw(
                peer_b.xid,
                RouteId(203),
                CBOR::from(3u8),
                RequestConfig::default(),
            )
            .recv()
            .await
            .unwrap();

        let first = response.body.next_chunk().await;
        match first {
            Ok(Some(_)) => {
                let second = response.body.next_chunk().await;
                assert!(matches!(second, Err(QlError::TransferCancelled { .. })));
            }
            Err(QlError::TransferCancelled { .. }) => {}
            other => panic!("unexpected first chunk result: {other:?}"),
        }

        let _ = responder_task.await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn request_upload_round_trip() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_request_timeout(Duration::from_millis(200));
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
            if let Ok(HandlerEvent::UploadRequest(request)) = inbound_b.recv().await {
                assert_eq!(request.route_id, RouteId(204));
                assert_eq!(request.meta, CBOR::from("meta"));
                let mut body = request.body;
                let mut bytes = Vec::new();
                while let Some(chunk) = body.next_chunk().await.unwrap() {
                    bytes.extend(chunk);
                }
                assert_eq!(bytes, vec![1, 2, 3, 4]);
                request.respond_to.respond(4u8).unwrap();
            }
        });

        let mut upload = handle_a
            .send_request_upload_raw(
                peer_b.xid,
                RouteId(204),
                CBOR::from("meta"),
                RequestConfig::default(),
            )
            .await
            .unwrap();
        upload.transfer.write_next(vec![1, 2]).await.unwrap();
        upload.transfer.write_next(vec![3, 4]).await.unwrap();
        upload.transfer.finish().await.unwrap();
        let response = upload.response.recv().await.unwrap();

        assert_eq!(response, CBOR::from(4u8));

        let _ = responder_task.await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn duplicate_open_response_resends_ack_without_cancelling_stream() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_request_timeout(Duration::from_millis(30));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_drop_first_transfer_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);

        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            if let Ok(HandlerEvent::Request(request)) = inbound_b.recv().await {
                let mut stream = request.respond_to.respond_stream(7u8).unwrap();
                stream.write_next(vec![1, 2, 3]).await.unwrap();
                stream.write_next(vec![4, 5]).await.unwrap();
                stream.finish().await.unwrap();
            }
        });

        let mut response = tokio::time::timeout(
            Duration::from_secs(1),
            handle_a
                .send_request_stream_raw(
                    peer_b.xid,
                    RouteId(205),
                    CBOR::from(1u8),
                    RequestConfig {
                        timeout: Some(Duration::from_millis(200)),
                    },
                )
                .recv(),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(response.meta, CBOR::from(7u8));
        assert_eq!(
            response.body.next_chunk().await.unwrap(),
            Some(vec![1, 2, 3])
        );
        assert_eq!(response.body.next_chunk().await.unwrap(), Some(vec![4, 5]));
        assert_eq!(response.body.next_chunk().await.unwrap(), None);

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn duplicate_open_request_retries_without_redispatching_upload() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_request_timeout(Duration::from_millis(30));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_drop_first_transfer_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);

        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            if let Ok(HandlerEvent::UploadRequest(request)) = inbound_b.recv().await {
                assert_eq!(request.route_id, RouteId(206));
                assert_eq!(request.meta, CBOR::from("meta"));
                let mut body = request.body;
                let mut bytes = Vec::new();
                while let Some(chunk) = body.next_chunk().await.unwrap() {
                    bytes.extend(chunk);
                }
                assert_eq!(bytes, vec![1, 2, 3, 4]);
                request.respond_to.respond(4u8).unwrap();
            }

            let second = tokio::time::timeout(Duration::from_millis(150), inbound_b.recv()).await;
            assert!(second.is_err(), "duplicate upload request dispatched");
        });

        let mut upload = tokio::time::timeout(
            Duration::from_secs(1),
            handle_a.send_request_upload_raw(
                peer_b.xid,
                RouteId(206),
                CBOR::from("meta"),
                RequestConfig {
                    timeout: Some(Duration::from_millis(200)),
                },
            ),
        )
        .await
        .unwrap()
        .unwrap();
        upload.transfer.write_next(vec![1, 2]).await.unwrap();
        upload.transfer.write_next(vec![3, 4]).await.unwrap();
        upload.transfer.finish().await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(1), upload.response.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(response, CBOR::from(4u8));

        tokio::time::timeout(Duration::from_secs(1), responder_task)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}
