use bc_components::SymmetricKey;

use super::*;
use crate::RouteId;

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

        handle_a.register_peer(
            peer_b,
            platform_b.signing_public_key().clone(),
            platform_b.encapsulation_public_key().clone(),
        );

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
        handle_a.connect(peer_b.xid).unwrap();

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
        handle_a.connect(peer_b.xid).unwrap();

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
        handle_a.connect(peer_b.xid).unwrap();

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
async fn any_call_clears_pending() {
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
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        tokio::time::timeout(Duration::from_millis(200), heartbeat_rx.recv())
            .await
            .unwrap()
            .unwrap();

        let responder_task = tokio::task::spawn_local(async move {
            let call = match inbound_a.recv().await.unwrap() {
                HandlerEvent::Call(call) => call,
            };
            let response = call.respond_to.accept(Vec::new()).unwrap();
            response.finish().await.unwrap();
        });

        let pending = handle_b
            .open_call(
                peer_a.xid,
                RouteId(99),
                Vec::new(),
                true,
                Default::default(),
            )
            .await
            .unwrap();
        pending.request.finish().await.unwrap();
        let _ = pending.accepted.recv().await.unwrap();

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
        handle_a.connect(peer_b.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let call = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Call(call) => call,
            };
            let response = call.respond_to.accept(Vec::new()).unwrap();
            response.finish().await.unwrap();
        });

        drop_flag.store(true, Ordering::Relaxed);

        let pending = handle_a
            .open_call(peer_b.xid, RouteId(9), Vec::new(), true, Default::default())
            .await
            .unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Disconnected).await;

        let result = tokio::time::timeout(Duration::from_millis(300), pending.accepted.recv())
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
        handle_a.connect(peer_b.xid).unwrap();

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
        handle_a.connect(peer_b.xid).unwrap();

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

#[tokio::test(flavor = "current_thread")]
async fn multi_peer_keepalive_disconnect_isolated() {
    run_local_test(async {
        let keep_alive = KeepAliveConfig {
            interval: Duration::from_millis(40),
            timeout: Duration::from_millis(60),
        };
        let config_a = RuntimeConfig::new(Duration::from_millis(200)).with_keep_alive(keep_alive);
        let config_b = RuntimeConfig::new(Duration::from_millis(200));
        let config_c = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let (platform_c, outbound_c, status_c) = TestPlatform::new(3);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);
        let peer_c = peer_identity(&platform_c);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);
        let (runtime_c, handle_c) = new_runtime(platform_c, config_c);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });
        tokio::task::spawn_local(async move { runtime_c.run().await });

        let drop_b_to_a = Arc::new(AtomicBool::new(false));
        spawn_routed_forwarder(
            outbound_a,
            vec![
                (peer_b.xid, handle_b.clone()),
                (peer_c.xid, handle_c.clone()),
            ],
        );
        spawn_routed_forwarder_with_filter(outbound_b, vec![(peer_a.xid, handle_a.clone())], {
            let drop_b_to_a = drop_b_to_a.clone();
            move |record| {
                !(drop_b_to_a.load(Ordering::Relaxed) && record.header.recipient == peer_a.xid)
            }
        });
        spawn_routed_forwarder(outbound_c, vec![(peer_a.xid, handle_a.clone())]);

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        register_peers(&handle_a, &handle_c, &peer_a, &peer_c);

        handle_a.connect(peer_b.xid).unwrap();
        handle_a.connect(peer_c.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_a, peer_c.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;
        await_status(&status_c, peer_a.xid, PeerStage::Connected).await;

        drop_b_to_a.store(true, Ordering::Relaxed);

        await_status(&status_a, peer_b.xid, PeerStage::Disconnected).await;

        let disconnect =
            tokio::time::timeout(keep_alive.timeout + Duration::from_millis(80), async {
                loop {
                    if let Ok(event) = status_a.recv().await {
                        if event.peer == peer_c.xid && event.stage == PeerStage::Disconnected {
                            return;
                        }
                    }
                }
            })
            .await;
        assert!(disconnect.is_err(), "unexpected disconnect for peer C");
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn multi_peer_disconnect_drops_outbound_for_one() {
    run_local_test(async {
        let keep_alive = KeepAliveConfig {
            interval: Duration::from_millis(40),
            timeout: Duration::from_millis(60),
        };
        let config_a = RuntimeConfig::new(Duration::from_millis(200))
            .with_keep_alive(keep_alive)
            .with_open_timeout(Duration::from_millis(250));
        let config_b = RuntimeConfig::new(Duration::from_millis(200));
        let config_c = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let (platform_c, outbound_c, status_c, inbound_c) = InboundPlatform::new(3);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);
        let peer_c = peer_identity(&platform_c);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);
        let (runtime_c, handle_c) = new_runtime(platform_c, config_c);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });
        tokio::task::spawn_local(async move { runtime_c.run().await });

        let drop_b_to_a = Arc::new(AtomicBool::new(false));
        spawn_routed_forwarder(
            outbound_a,
            vec![
                (peer_b.xid, handle_b.clone()),
                (peer_c.xid, handle_c.clone()),
            ],
        );
        spawn_routed_forwarder_with_filter(outbound_b, vec![(peer_a.xid, handle_a.clone())], {
            let drop_b_to_a = drop_b_to_a.clone();
            move |record| {
                !(drop_b_to_a.load(Ordering::Relaxed) && record.header.recipient == peer_a.xid)
            }
        });
        spawn_routed_forwarder(outbound_c, vec![(peer_a.xid, handle_a.clone())]);

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        register_peers(&handle_a, &handle_c, &peer_a, &peer_c);

        handle_a.connect(peer_b.xid).unwrap();
        handle_a.connect(peer_c.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_a, peer_c.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;
        await_status(&status_c, peer_a.xid, PeerStage::Connected).await;

        let inbound_task = tokio::task::spawn_local(async move {
            let call = match inbound_c.recv().await.unwrap() {
                HandlerEvent::Call(call) => call,
            };
            let response = call.respond_to.accept(Vec::new()).unwrap();
            response.finish().await.unwrap();
        });

        drop_b_to_a.store(true, Ordering::Relaxed);

        let pending_b = handle_a
            .open_call(
                peer_b.xid,
                RouteId(10),
                Vec::new(),
                true,
                Default::default(),
            )
            .await
            .unwrap();
        let pending_c = handle_a
            .open_call(
                peer_c.xid,
                RouteId(11),
                Vec::new(),
                true,
                Default::default(),
            )
            .await
            .unwrap();

        let accepted_c =
            tokio::time::timeout(Duration::from_millis(200), pending_c.accepted.recv())
                .await
                .expect("response wait")
                .expect("response channel");
        pending_c.request.finish().await.unwrap();
        drop(accepted_c);

        await_status(&status_a, peer_b.xid, PeerStage::Disconnected).await;

        let result_b = tokio::time::timeout(Duration::from_millis(200), pending_b.accepted.recv())
            .await
            .expect("response wait");
        assert!(matches!(result_b, Err(QlError::SendFailed)));

        let _ = inbound_task.await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn multi_peer_activity_is_per_peer() {
    run_local_test(async {
        let keep_alive = KeepAliveConfig {
            interval: Duration::from_millis(100),
            timeout: Duration::from_millis(40),
        };
        let config_a = RuntimeConfig::new(Duration::from_millis(200)).with_keep_alive(keep_alive);
        let config_b = RuntimeConfig::new(Duration::from_millis(200));
        let config_c = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a, inbound_a) = InboundPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let (platform_c, outbound_c, status_c) = TestPlatform::new(3);
        let peer_a = peer_identity(&platform_a);
        let peer_b = peer_identity(&platform_b);
        let peer_c = peer_identity(&platform_c);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);
        let (runtime_c, handle_c) = new_runtime(platform_c, config_c);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });
        tokio::task::spawn_local(async move { runtime_c.run().await });

        let drop_all_c = Arc::new(AtomicBool::new(false));
        spawn_routed_forwarder(
            outbound_a,
            vec![
                (peer_b.xid, handle_b.clone()),
                (peer_c.xid, handle_c.clone()),
            ],
        );
        spawn_drop_heartbeat_forwarder(outbound_b, handle_a.clone());
        spawn_gated_forwarder(outbound_c, handle_a.clone(), drop_all_c.clone());

        register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        register_peers(&handle_a, &handle_c, &peer_a, &peer_c);

        handle_a.connect(peer_b.xid).unwrap();
        handle_a.connect(peer_c.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_a, peer_c.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;
        await_status(&status_c, peer_a.xid, PeerStage::Connected).await;

        drop_all_c.store(true, Ordering::Relaxed);

        tokio::time::sleep(keep_alive.interval + Duration::from_millis(5)).await;

        let responder_task = tokio::task::spawn_local(async move {
            let call = match inbound_a.recv().await.unwrap() {
                HandlerEvent::Call(call) => call,
            };
            let response = call.respond_to.accept(Vec::new()).unwrap();
            response.finish().await.unwrap();
        });

        let pending = handle_b
            .open_call(
                peer_a.xid,
                RouteId(99),
                Vec::new(),
                true,
                Default::default(),
            )
            .await
            .unwrap();
        pending.request.finish().await.unwrap();
        let _ = pending.accepted.recv().await.unwrap();

        await_status(&status_a, peer_c.xid, PeerStage::Disconnected).await;

        let disconnect =
            tokio::time::timeout(keep_alive.timeout + Duration::from_millis(30), async {
                loop {
                    if let Ok(event) = status_a.recv().await {
                        if event.peer == peer_b.xid && event.stage == PeerStage::Disconnected {
                            return;
                        }
                    }
                }
            })
            .await;
        assert!(disconnect.is_err(), "unexpected disconnect for peer B");

        let _ = responder_task.await;
    })
    .await;
}
