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

        handle_a.register_peer(
            peer_b,
            platform_b.signing_public_key().clone(),
            platform_b.encapsulation_public_key().clone(),
        );

        let heartbeat = crypto_heartbeat::encrypt_heartbeat(
            QlHeader {
                sender: peer_b,
                recipient: peer_a,
            },
            &SymmetricKey::new(),
            HeartbeatBody {
                message_id: MessageId::new(1),
                valid_until: now_secs().saturating_add(60),
            },
        );
        let bytes = CBOR::from(heartbeat).to_cbor_data();
        handle_a.send_incoming(bytes);

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

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_tx, heartbeat_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_tx);
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

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

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_tx, heartbeat_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_tx);
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let _ = tokio::time::timeout(Duration::from_millis(200), heartbeat_rx.recv())
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

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_ab_tx, heartbeat_ab_rx) = async_channel::unbounded();
        let (heartbeat_ba_tx, heartbeat_ba_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_ab_tx);
        spawn_heartbeat_tap_forwarder(outbound_b, handle_a.clone(), heartbeat_ba_tx);

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let _ = tokio::time::timeout(Duration::from_millis(200), heartbeat_ab_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_millis(200), heartbeat_ba_rx.recv())
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn any_message_clears_pending() {
    run_local_test(async {
        let keep_alive = KeepAliveConfig {
            interval: Duration::from_millis(120),
            timeout: Duration::from_millis(40),
        };
        let config_a = RuntimeConfig::new(Duration::from_millis(200)).with_keep_alive(keep_alive);
        let config_b = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_tx, heartbeat_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_tx);
        spawn_drop_heartbeat_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let _ = tokio::time::timeout(Duration::from_millis(200), heartbeat_rx.recv())
            .await
            .unwrap()
            .unwrap();

        handle_b.send_event_raw(peer_a, RouteId::new(99), CBOR::from(1u8));

        let window = keep_alive.timeout + Duration::from_millis(20);
        let disconnect = tokio::time::timeout(window, async {
            loop {
                if let Ok(event) = status_a.recv().await {
                    if event.peer == peer_b && event.stage == PeerStage::Disconnected {
                        return;
                    }
                }
            }
        })
        .await;
        assert!(disconnect.is_err(), "unexpected disconnect");
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
        let config_a = RuntimeConfig::new(Duration::from_millis(200)).with_keep_alive(keep_alive);
        let config_b = RuntimeConfig::new(Duration::from_millis(200));
        let (platform_a, outbound_a, status_a) = TestPlatform::new(2);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(1);

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let drop_flag = Arc::new(AtomicBool::new(false));
        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_gated_forwarder(outbound_b, handle_a.clone(), drop_flag.clone());

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        drop_flag.store(true, Ordering::Relaxed);

        let response = handle_a.send_request_raw(
            peer_b,
            RouteId::new(9),
            CBOR::from(9u8),
            RequestConfig {
                timeout: Some(Duration::from_millis(200)),
            },
        );

        await_status(&status_a, peer_b, PeerStage::Disconnected).await;

        let result = tokio::time::timeout(Duration::from_millis(300), response.recv())
            .await
            .unwrap();
        assert!(
            matches!(result, Err(QlError::SendFailed)),
            "unexpected result: {result:?}"
        );
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

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_ab_tx, heartbeat_ab_rx) = async_channel::unbounded();
        let (heartbeat_ba_tx, heartbeat_ba_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_ab_tx);
        spawn_heartbeat_tap_forwarder(outbound_b, handle_a.clone(), heartbeat_ba_tx);

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let _ = tokio::time::timeout(Duration::from_millis(300), heartbeat_ab_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_millis(200), heartbeat_ba_rx.recv())
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

        let signing_a = platform_a.signing_public_key().clone();
        let signing_b = platform_b.signing_public_key().clone();
        let encap_a = platform_a.encapsulation_public_key().clone();
        let encap_b = platform_b.encapsulation_public_key().clone();
        let peer_a = XID::new(&signing_a);
        let peer_b = XID::new(&signing_b);

        let (runtime_a, handle_a) = new_runtime(platform_a, config);
        let (runtime_b, handle_b) = new_runtime(platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_tx, heartbeat_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_tx);
        spawn_forwarder(outbound_b, handle_a.clone());

        handle_a.register_peer(peer_b, signing_b.clone(), encap_b.clone());
        handle_b.register_peer(peer_a, signing_a.clone(), encap_a.clone());

        handle_a.connect(peer_b).unwrap();

        await_status(&status_a, peer_b, PeerStage::Connected).await;
        await_status(&status_b, peer_a, PeerStage::Connected).await;

        let heartbeat = crypto_heartbeat::encrypt_heartbeat(
            QlHeader {
                sender: peer_b,
                recipient: peer_a,
            },
            &SymmetricKey::new(),
            HeartbeatBody {
                message_id: MessageId::new(42),
                valid_until: now_secs().saturating_add(30),
            },
        );
        let bytes = CBOR::from(heartbeat).to_cbor_data();
        handle_a.send_incoming(bytes);

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

        let _ = register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        let _ = register_peers(&handle_a, &handle_c, &peer_a, &peer_c);

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
        let config_a = RuntimeConfig::new(Duration::from_millis(200)).with_keep_alive(keep_alive);
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

        let _ = register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        let _ = register_peers(&handle_a, &handle_c, &peer_a, &peer_c);

        handle_a.connect(peer_b.xid).unwrap();
        handle_a.connect(peer_c.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_a, peer_c.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;
        await_status(&status_c, peer_a.xid, PeerStage::Connected).await;

        let inbound_task = tokio::task::spawn_local(async move {
            if let Ok(HandlerEvent::Request(request)) = inbound_c.recv().await {
                let _ = request.respond_to.respond(55u8);
            }
        });

        drop_b_to_a.store(true, Ordering::Relaxed);

        let request_b = handle_a.send_request_raw(
            peer_b.xid,
            RouteId::new(10),
            CBOR::from(10u8),
            RequestConfig {
                timeout: Some(Duration::from_millis(200)),
            },
        );
        let request_c = handle_a.send_request_raw(
            peer_c.xid,
            RouteId::new(11),
            CBOR::from(11u8),
            RequestConfig {
                timeout: Some(Duration::from_millis(200)),
            },
        );

        let response_c = tokio::time::timeout(Duration::from_millis(200), request_c.recv())
            .await
            .expect("response wait")
            .expect("response channel");
        let value: u8 = response_c.try_into().unwrap();
        assert_eq!(value, 55u8);

        await_status(&status_a, peer_b.xid, PeerStage::Disconnected).await;

        let result_b = tokio::time::timeout(Duration::from_millis(200), request_b.recv())
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

        let _ = register_peers(&handle_a, &handle_b, &peer_a, &peer_b);
        let _ = register_peers(&handle_a, &handle_c, &peer_a, &peer_c);

        handle_a.connect(peer_b.xid).unwrap();
        handle_a.connect(peer_c.xid).unwrap();

        await_status(&status_a, peer_b.xid, PeerStage::Connected).await;
        await_status(&status_a, peer_c.xid, PeerStage::Connected).await;
        await_status(&status_b, peer_a.xid, PeerStage::Connected).await;
        await_status(&status_c, peer_a.xid, PeerStage::Connected).await;

        drop_all_c.store(true, Ordering::Relaxed);

        tokio::time::sleep(keep_alive.interval + Duration::from_millis(5)).await;

        handle_b.send_event_raw(peer_a.xid, RouteId::new(99), CBOR::from(1u8));

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
    })
    .await;
}
