use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn session_timeout_disconnects_and_fails_pending_open() {
    run_local_test(async {
        let config_a = RuntimeConfig {
            fsm: QlFsmConfig {
                session_keepalive_interval: Duration::from_millis(40),
                session_peer_timeout: Duration::from_millis(60),
                ..default_runtime_config().fsm
            },
            ..default_runtime_config()
        };
        let config_b = default_runtime_config();
        let (platform_a, outbound_a, status_a) = TestPlatform::new(2);
        let (platform_b, outbound_b, status_b, inbound_b) = TestPlatform::new_with_inbound(1);
        let identity_a = new_identity(11);
        let identity_b = new_identity(73);

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
            let stream = inbound_b.recv().await.unwrap();
            let _ = read_all(stream.reader).await;
            let _ = stream.writer.finish().await;
        });

        drop_flag.store(true, Ordering::Relaxed);

        let mut pending = handle_a.open_stream().await.unwrap();
        pending.writer.finish().await.unwrap();

        await_status(&status_a, identity_b.xid, PeerStage::Disconnected).await;

        let result =
            tokio::time::timeout(Duration::from_millis(300), next_chunk(&mut pending.reader))
                .await
                .unwrap();
        assert!(matches!(
            result,
            Err(QlError::SessionClosed | QlError::Cancelled)
        ));

        responder_task.abort();
    })
    .await;
}
