use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn keepalive_disabled_no_heartbeat() {
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

        let (heartbeat_tx, heartbeat_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_tx);
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect().unwrap();

        await_status(&status_a, identity_b.xid, PeerStage::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStage::Connected).await;

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
        let config_a = RuntimeConfig {
            engine: crate::engine::EngineConfig {
                keep_alive: Some(keep_alive),
                ..default_runtime_config().engine
            },
            ..default_runtime_config()
        };
        let config_b = default_runtime_config();
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let identity_a = new_identity();
        let identity_b = new_identity();

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_tx, heartbeat_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_tx);
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect().unwrap();

        await_status(&status_a, identity_b.xid, PeerStage::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStage::Connected).await;

        tokio::time::timeout(Duration::from_millis(200), heartbeat_rx.recv())
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn stream_activity_prevents_keepalive_timeout() {
    run_local_test(async {
        let keep_alive = KeepAliveConfig {
            interval: Duration::from_millis(120),
            timeout: Duration::from_millis(40),
        };
        let config_a = RuntimeConfig {
            engine: crate::engine::EngineConfig {
                keep_alive: Some(keep_alive),
                ..default_runtime_config().engine
            },
            ..default_runtime_config()
        };
        let config_b = default_runtime_config();
        let (platform_a, outbound_a, status_a, inbound_a) = TestPlatform::new_with_inbound(1);
        let (platform_b, outbound_b, status_b) = TestPlatform::new(2);
        let identity_a = new_identity();
        let identity_b = new_identity();

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let (heartbeat_tx, heartbeat_rx) = async_channel::unbounded();
        spawn_heartbeat_tap_forwarder(outbound_a, handle_b.clone(), heartbeat_tx);
        spawn_drop_heartbeat_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect().unwrap();

        await_status(&status_a, identity_b.xid, PeerStage::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStage::Connected).await;

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

        let stream = handle_b.open_stream(Vec::new(), crate::runtime::StreamConfig::default()).await;
        let mut stream = stream.unwrap();
        stream.inbound.finish().await.unwrap();
        assert_eq!(stream.outbound.next_chunk().await.unwrap(), None);

        let disconnect = tokio::time::timeout(keep_alive.timeout + Duration::from_millis(20), async {
            loop {
                if let Ok(event) = status_a.recv().await {
                    if event.peer == identity_b.xid && event.stage == PeerStage::Disconnected {
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
async fn heartbeat_timeout_disconnects_and_fails_pending_open() {
    run_local_test(async {
        let keep_alive = KeepAliveConfig {
            interval: Duration::from_millis(80),
            timeout: Duration::from_millis(60),
        };
        let config_a = RuntimeConfig {
            engine: crate::engine::EngineConfig {
                keep_alive: Some(keep_alive),
                ..default_runtime_config().engine
            },
            ..default_runtime_config()
        };
        let config_b = default_runtime_config();
        let (platform_a, outbound_a, status_a) = TestPlatform::new(2);
        let (platform_b, outbound_b, status_b, inbound_b) = TestPlatform::new_with_inbound(1);
        let identity_a = new_identity();
        let identity_b = new_identity();

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let drop_flag = Arc::new(AtomicBool::new(false));
        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_gated_forwarder(outbound_b, handle_a.clone(), drop_flag.clone());

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect().unwrap();

        await_status(&status_a, identity_b.xid, PeerStage::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStage::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let response = stream.respond_to.accept(Vec::new()).unwrap();
            response.finish().await.unwrap();
        });

        drop_flag.store(true, Ordering::Relaxed);

        let mut pending = handle_a
            .open_stream(Vec::new(), crate::runtime::StreamConfig::default())
            .await
            .unwrap();

        await_status(&status_a, identity_b.xid, PeerStage::Disconnected).await;

        let result = tokio::time::timeout(Duration::from_millis(300), pending.outbound.next_chunk())
            .await;
        assert!(result.is_ok(), "pending stream never resolved after disconnect");

        responder_task.abort();
    })
    .await;
}
