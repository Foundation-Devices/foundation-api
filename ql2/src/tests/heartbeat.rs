use bc_components::SymmetricKey;

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn heartbeat_ignored_without_session() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, _status_a) = TestPlatform::new(1);
        let (platform_b, _outbound_b, _status_b) = TestPlatform::new(2);

        let peer_a = platform_a.xid();
        let peer_b = platform_b.xid();

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        tokio::task::spawn_local(async move { runtime_a.run().await });

        handle_a.bind_peer(Peer {
            peer: peer_b,
            signing_key: platform_b.signing_public_key().clone(),
            encapsulation_key: platform_b.encapsulation_public_key().clone(),
        });

        let heartbeat = wire::heartbeat::encrypt_heartbeat(
            QlHeader {
                sender: peer_b,
                recipient: peer_a,
            },
            &SymmetricKey::new(),
            HeartbeatBody {
                message_id: MessageId(1),
                valid_until: now_secs().saturating_add(60),
            },
        );
        handle_a.send_incoming(CBOR::from(heartbeat).to_cbor_data());

        let result = tokio::time::timeout(Duration::from_millis(50), outbound_a.recv()).await;
        assert!(result.is_err(), "expected heartbeat to be ignored");
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn keepalive_disabled_no_heartbeat() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_tx, heartbeat_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_tx);
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect().unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let result = tokio::time::timeout(Duration::from_millis(120), heartbeat_rx.recv()).await;
        assert!(result.is_err(), "unexpected heartbeat while disabled");
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn heartbeat_sent_after_idle() {
    run_local_test(async {
        let keep_alive = KeepAliveConfig {
            interval: Duration::from_millis(30),
            timeout: Duration::from_millis(80),
        };
        let config_a = RuntimeConfig::new(Duration::from_millis(200)).with_keep_alive(keep_alive);
        let config_b = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_tx, heartbeat_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_tx);
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect().unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        tokio::time::timeout(Duration::from_millis(200), heartbeat_rx.recv())
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn heartbeat_reply_when_connected() {
    run_local_test(async {
        let keep_alive = KeepAliveConfig {
            interval: Duration::from_millis(30),
            timeout: Duration::from_millis(80),
        };
        let config_a = RuntimeConfig::new(Duration::from_millis(200)).with_keep_alive(keep_alive);
        let config_b = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_ab_tx, heartbeat_ab_rx) = async_channel::unbounded();
        let (heartbeat_ba_tx, heartbeat_ba_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_ab_tx);
        spawn_heartbeat_tap_forwarder(outbound_b, handle_a.clone(), heartbeat_ba_tx);

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect().unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        tokio::time::timeout(Duration::from_millis(200), heartbeat_ab_rx.recv())
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_millis(200), heartbeat_ba_rx.recv())
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn any_stream_clears_pending() {
    run_local_test(async {
        let keep_alive = KeepAliveConfig {
            interval: Duration::from_millis(120),
            timeout: Duration::from_millis(40),
        };
        let config_a = RuntimeConfig::new(Duration::from_millis(200)).with_keep_alive(keep_alive);
        let config_b = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a, inbound_a) = InboundPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_tx, heartbeat_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_tx);
        spawn_drop_heartbeat_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect().unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        tokio::time::timeout(Duration::from_millis(200), heartbeat_rx.recv())
            .await
            .unwrap()
            .unwrap();

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_a.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let response = stream.respond_to.accept(Vec::new()).unwrap();
            response.finish().await.unwrap();
        });

        let pending = handle_b
            .open_stream(Vec::new(), Default::default())
            .await
            .unwrap();
        pending.request.finish().await.unwrap();
        let _ = pending.accepted.await.unwrap();

        let window = keep_alive.timeout + Duration::from_millis(20);
        let disconnect = tokio::time::timeout(window, async {
            loop {
                if let Ok(event) = status_a.recv().await {
                    if event.peer == peer_b.xid && event.stage == PeerStage::Disconnected {
                        return;
                    }
                }
            }
        })
        .await;
        assert!(disconnect.is_err(), "unexpected disconnect");

        let _ = responder_task.await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn heartbeat_timeout_disconnects_and_drops_outbound() {
    run_local_test(async {
        let keep_alive = KeepAliveConfig {
            interval: Duration::from_millis(80),
            timeout: Duration::from_millis(60),
        };
        let config_a = RuntimeConfig::new(Duration::from_millis(200))
            .with_keep_alive(keep_alive)
            .with_open_timeout(Duration::from_millis(300));
        let config_b = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(2);
        let (platform_b, outbound_b, status_b, inbound_b) = InboundPlatform::new(1);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let drop_flag = Arc::new(AtomicBool::new(false));
        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_gated_forwarder(outbound_b, handle_a.clone(), drop_flag.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect().unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let response = stream.respond_to.accept(Vec::new()).unwrap();
            response.finish().await.unwrap();
        });

        drop_flag.store(true, Ordering::Relaxed);

        let pending = handle_a
            .open_stream(Vec::new(), Default::default())
            .await
            .unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Disconnected).await;

        let result = tokio::time::timeout(Duration::from_millis(300), pending.accepted)
            .await
            .unwrap();
        assert!(matches!(result, Err(QlError::SendFailed)));

        responder_task.abort();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn no_ping_pong() {
    run_local_test(async {
        let keep_alive = KeepAliveConfig {
            interval: Duration::from_millis(200),
            timeout: Duration::from_millis(60),
        };
        let config_a = RuntimeConfig::new(Duration::from_millis(200)).with_keep_alive(keep_alive);
        let config_b = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_ab_tx, heartbeat_ab_rx) = async_channel::unbounded();
        let (heartbeat_ba_tx, heartbeat_ba_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_ab_tx);
        spawn_heartbeat_tap_forwarder(outbound_b, handle_a.clone(), heartbeat_ba_tx);

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect().unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        tokio::time::timeout(Duration::from_millis(300), heartbeat_ab_rx.recv())
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_millis(200), heartbeat_ba_rx.recv())
            .await
            .unwrap()
            .unwrap();

        let followup =
            tokio::time::timeout(Duration::from_millis(50), heartbeat_ab_rx.recv()).await;
        assert!(followup.is_err(), "unexpected heartbeat ping-pong");
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_heartbeat_ignored() {
    run_local_test(async {
        let config = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_tx, heartbeat_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_tx);
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        handle_a.connect().unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let heartbeat = wire::heartbeat::encrypt_heartbeat(
            QlHeader {
                sender: peer_b.xid,
                recipient: peer_a.xid,
            },
            &SymmetricKey::new(),
            HeartbeatBody {
                message_id: MessageId(42),
                valid_until: now_secs().saturating_add(30),
            },
        );
        handle_a.send_incoming(CBOR::from(heartbeat).to_cbor_data());

        let result = tokio::time::timeout(Duration::from_millis(50), heartbeat_rx.recv()).await;
        assert!(result.is_err(), "unexpected heartbeat reply");
    })
    .await;
}
