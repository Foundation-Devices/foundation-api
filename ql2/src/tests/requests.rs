use super::*;

fn spawn_delayed_message_forwarder(
    outbound: Receiver<Vec<u8>>,
    handle: RuntimeHandle,
    delay: Duration,
) {
    tokio::task::spawn_local(async move {
        while let Ok(bytes) = outbound.recv().await {
            let is_message = CBOR::try_from_data(&bytes)
                .and_then(QlRecord::try_from)
                .is_ok_and(|record| matches!(record.payload, QlPayload::Message(_)));
            if is_message {
                tokio::time::sleep(delay).await;
            }
            handle.send_incoming(bytes);
        }
    });
}

#[tokio::test(flavor = "current_thread")]
async fn request_response_round_trip() {
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

        let inbound_task = tokio::task::spawn_local(async move {
            if let Ok(HandlerEvent::Request(request)) = inbound_b.recv().await {
                let _ = request.respond_to.respond(99u8);
            }
        });

        let response = handle_a.send_request_raw(
            peer_b.xid,
            RouteId(7),
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

        let ticket = handle_a.send_request_raw(
            peer_b.xid,
            RouteId(1),
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

        let inbound_task = tokio::task::spawn_local(async move {
            if let Ok(HandlerEvent::Request(request)) = inbound_b.recv().await {
                let _ = request.respond_to.respond_nack(Nack::InvalidPayload);
            }
        });

        let response = handle_a.send_request_raw(
            peer_b.xid,
            RouteId(2),
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

        let inbound_task = tokio::task::spawn_local(async move {
            if let Ok(HandlerEvent::Request(request)) = inbound_b.recv().await {
                let _ = request.respond_to.respond(7u8);
            }
        });

        let ticket = handle_a.send_request_raw(
            peer_b.xid,
            RouteId(3),
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

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        tokio::task::spawn_local({
            let handle_b = handle_b.clone();
            async move {
                while let Ok(bytes) = outbound_a.recv().await {
                    let Ok(record) = CBOR::try_from_data(&bytes).and_then(QlRecord::try_from)
                    else {
                        handle_b.send_incoming(bytes);
                        continue;
                    };
                    if matches!(record.payload, QlPayload::Message(_)) {
                        handle_b.send_incoming(bytes.clone());
                        handle_b.send_incoming(bytes);
                        continue;
                    }
                    handle_b.send_incoming(bytes);
                }
            }
        });
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);

        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        handle_a.send_event_raw(peer_b.xid, RouteId(9), CBOR::from(1u8));

        let first = tokio::time::timeout(Duration::from_secs(1), inbound_b.recv())
            .await
            .unwrap()
            .unwrap();
        match first {
            HandlerEvent::Event(event) => {
                assert_eq!(event.message.route_id, RouteId(9));
            }
            HandlerEvent::Request(_) => panic!("unexpected request"),
            HandlerEvent::UploadRequest(_) => panic!("unexpected upload request"),
        }

        let second = tokio::time::timeout(Duration::from_millis(50), inbound_b.recv()).await;
        assert!(second.is_err(), "replay delivered a second event");
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn expired_request_returns_expired_nack() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_message_expiration(Duration::from_secs(1))
            .with_request_timeout(Duration::from_secs(3));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_delayed_message_forwarder(outbound_a, handle_b.clone(), Duration::from_millis(2000));
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);

        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let ticket = handle_a.send_request_raw(
            peer_b.xid,
            RouteId(4),
            CBOR::from(1u8),
            RequestConfig::default(),
        );

        let result = tokio::time::timeout(Duration::from_secs(5), ticket.recv())
            .await
            .unwrap();
        assert!(matches!(
            result,
            Err(QlError::Nack {
                nack: Nack::Expired,
                ..
            })
        ));
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn expired_event_does_not_send_nack() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200))
            .with_message_expiration(Duration::from_secs(1))
            .with_request_timeout(Duration::from_secs(3));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_delayed_message_forwarder(outbound_a, handle_b.clone(), Duration::from_millis(1500));

        let (message_tx, message_rx) = async_channel::unbounded();
        tokio::task::spawn_local({
            let handle_a = handle_a.clone();
            async move {
                while let Ok(bytes) = outbound_b.recv().await {
                    let is_message = CBOR::try_from_data(&bytes)
                        .and_then(QlRecord::try_from)
                        .is_ok_and(|record| matches!(record.payload, QlPayload::Message(_)));
                    if is_message {
                        let _ = message_tx.send(()).await;
                    }
                    handle_a.send_incoming(bytes);
                }
            }
        });

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);

        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        handle_a.send_event_raw(peer_b.xid, RouteId(10), CBOR::from(2u8));

        let unexpected = tokio::time::timeout(Duration::from_secs(3), message_rx.recv()).await;
        assert!(
            unexpected.is_err(),
            "expired event should not generate nack"
        );
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn session_reset_fails_queued_request() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(60));
        let (platform_a, outbound_a, status_a, write_gate) = BlockingPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);
        let (reset_hello, _secret) = wire::handshake::build_hello(
            &platform_b,
            peer_b.xid,
            peer_a.xid,
            &peer_a.encapsulation_key,
        )
        .unwrap();

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);

        write_gate.add_permits(2);
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let blocked = handle_a.send_request_raw(
            peer_b.xid,
            RouteId(12),
            CBOR::from(12u8),
            RequestConfig {
                timeout: Some(Duration::from_millis(200)),
            },
        );
        let queued = handle_a.send_request_raw(
            peer_b.xid,
            RouteId(13),
            CBOR::from(13u8),
            RequestConfig {
                timeout: Some(Duration::from_millis(200)),
            },
        );

        let hello_message = QlRecord {
            header: QlHeader {
                sender: peer_b.xid,
                recipient: peer_a.xid,
            },
            payload: QlPayload::Handshake(HandshakeRecord::Hello(reset_hello)),
        };
        handle_a.send_incoming(CBOR::from(hello_message).to_cbor_data());

        await_status(&status_a, peer_b.xid, PeerStage::Responder).await;
        await_status(&status_a, peer_b.xid, PeerStage::Disconnected).await;

        let queued_result = tokio::time::timeout(Duration::from_millis(300), queued.recv())
            .await
            .unwrap();
        assert!(matches!(queued_result, Err(QlError::Timeout)));

        let blocked_result = tokio::time::timeout(Duration::from_millis(300), blocked.recv())
            .await
            .unwrap();
        assert!(matches!(blocked_result, Err(QlError::Timeout)));
    })
    .await;
}
