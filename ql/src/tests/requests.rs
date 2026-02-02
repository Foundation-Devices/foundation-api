use super::*;

#[tokio::test(flavor = "current_thread")]
async fn request_response_round_trip() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_request_timeout(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config.clone());
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);

        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let inbound_task = tokio::task::spawn_local(async move {
            if let Ok(HandlerEvent::Request(request)) = inbound_b.recv().await {
                let _ = request.respond_to.respond(99u8);
            }
        });

        let response = handle_a.send_request_raw(
            peer_b.xid,
            RouteId::new(7),
            CBOR::from(12u8),
            RequestConfig::default(),
        );

        let response = response.recv().await.unwrap();
        let value: u8 = response.try_into().unwrap();
        assert_eq!(value, 99u8);
        let _ = inbound_task.await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn request_timeout_returns_error() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_request_timeout(Duration::from_millis(30));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config.clone());
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);

        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let ticket = handle_a.send_request_raw(
            peer_b.xid,
            RouteId::new(1),
            CBOR::from(1u8),
            RequestConfig {
                timeout: Some(Duration::from_millis(30)),
            },
        );

        let result = tokio::time::timeout(Duration::from_millis(200), ticket.recv())
            .await
            .unwrap();
        assert!(matches!(result, Err(QlError::Timeout)));
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn request_nack_resolves_pending() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_request_timeout(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config.clone());
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);

        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let inbound_task = tokio::task::spawn_local(async move {
            if let Ok(HandlerEvent::Request(request)) = inbound_b.recv().await {
                let _ = request.respond_to.respond_nack(Nack::InvalidPayload);
            }
        });

        let response = handle_a.send_request_raw(
            peer_b.xid,
            RouteId::new(2),
            CBOR::from(2u8),
            RequestConfig::default(),
        );

        let result = response.recv().await;
        assert!(matches!(
            result,
            Err(QlError::Nack {
                nack: Nack::InvalidPayload,
                ..
            })
        ));
        let _ = inbound_task.await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn request_dispatches_to_platform_callback() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_request_timeout(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config.clone());
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);

        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let inbound_task = tokio::task::spawn_local(async move {
            if let Ok(HandlerEvent::Request(request)) = inbound_b.recv().await {
                let _ = request.respond_to.respond(7u8);
            }
        });

        let ticket = handle_a.send_request_raw(
            peer_b.xid,
            RouteId::new(3),
            CBOR::from(1u8),
            RequestConfig::default(),
        );

        let response = ticket.recv().await.unwrap();
        let value: u8 = response.try_into().unwrap();
        assert_eq!(value, 7u8);
        let _ = inbound_task.await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn replayed_message_is_ignored() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config.clone());
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        tokio::task::spawn_local({
            let handle_b = handle_b.clone();
            async move {
                while let Ok(bytes) = outbound_a.recv().await {
                    let Ok(record) = CBOR::try_from_data(&bytes).and_then(QlRecord::try_from)
                    else {
                        let _ = handle_b.send_incoming(bytes);
                        continue;
                    };
                    if matches!(record.payload, QlPayload::Message(_)) {
                        let _ = handle_b.send_incoming(bytes.clone());
                        let _ = handle_b.send_incoming(bytes);
                        continue;
                    }
                    let _ = handle_b.send_incoming(bytes);
                }
            }
        });
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);

        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        handle_a.send_event_raw(peer_b.xid, RouteId::new(9), CBOR::from(1u8));

        let first = tokio::time::timeout(Duration::from_secs(1), inbound_b.recv())
            .await
            .unwrap()
            .unwrap();
        match first {
            HandlerEvent::Event(event) => {
                assert_eq!(event.message.route_id, RouteId::new(9));
            }
            HandlerEvent::Request(_) => panic!("unexpected request"),
        }

        let second = tokio::time::timeout(Duration::from_millis(50), inbound_b.recv()).await;
        assert!(second.is_err(), "replay delivered a second event");
    })
    .await;
}
