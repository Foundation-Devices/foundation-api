use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use bytes::Bytes;
use ql_wire::SessionCloseCode;

use super::*;
use crate::QlStreamError;

#[tokio::test(flavor = "current_thread")]
async fn close_session_aborts_active_streams_and_allows_reconnect() {
    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        let inbound_b = pair.take_inbound(Side::B);
        let (received_tx, received_rx) = async_channel::bounded(1);
        pair.connect_and_wait(Side::A).await;

        let responder = tokio::task::spawn_local(async move {
            let stream = inbound_b.recv().await.unwrap();
            let mut reader = stream.reader;

            assert_eq!(
                next_chunk(&mut reader).await.unwrap(),
                Some(vec![1, 2, 3, 4])
            );
            received_tx.send(()).await.unwrap();

            let err = next_chunk(&mut reader).await.unwrap_err();
            assert_eq!(err, QlStreamError::NoSession);
        });

        let mut stream = pair
            .side(Side::A)
            .handle
            .open_stream(test_route_id())
            .await
            .unwrap();
        stream
            .writer
            .write(Bytes::from_static(&[1, 2, 3, 4]))
            .await
            .unwrap();
        received_rx.recv().await.unwrap();

        pair.side(Side::A)
            .handle
            .close_session(SessionCloseCode::CANCELLED);

        let err = stream.writer.finish().await.unwrap_err();
        assert_eq!(err, QlStreamError::NoSession);

        await_status(
            &pair.side(Side::A).status,
            Some(pair.side(Side::B).peer),
            PeerStatus::Disconnected,
        )
        .await;
        await_status(
            &pair.side(Side::B).status,
            Some(pair.side(Side::A).peer),
            PeerStatus::Disconnected,
        )
        .await;

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();

        pair.connect_and_wait(Side::A).await;
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn unpair_aborts_active_streams_and_prevents_reconnect() {
    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        let inbound_b = pair.take_inbound(Side::B);
        let (received_tx, received_rx) = async_channel::bounded(1);
        pair.connect_and_wait(Side::A).await;

        let responder = tokio::task::spawn_local(async move {
            let stream = inbound_b.recv().await.unwrap();
            let mut reader = stream.reader;

            assert_eq!(
                next_chunk(&mut reader).await.unwrap(),
                Some(vec![5, 6, 7, 8])
            );
            received_tx.send(()).await.unwrap();

            let err = next_chunk(&mut reader).await.unwrap_err();
            assert_eq!(err, QlStreamError::NoSession);
        });

        let mut stream = pair
            .side(Side::A)
            .handle
            .open_stream(test_route_id())
            .await
            .unwrap();
        stream
            .writer
            .write(Bytes::from_static(&[5, 6, 7, 8]))
            .await
            .unwrap();
        received_rx.recv().await.unwrap();

        pair.side(Side::A).handle.unpair();

        let err = stream.writer.finish().await.unwrap_err();
        assert_eq!(err, QlStreamError::NoSession);

        await_status(&pair.side(Side::A).status, None, PeerStatus::Unpaired).await;
        await_status(&pair.side(Side::B).status, None, PeerStatus::Unpaired).await;

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(
            pair.side(Side::A).handle.open_stream(test_route_id()).await,
            Err(NoSessionError)
        ));
        assert!(matches!(
            pair.side(Side::B).handle.open_stream(test_route_id()).await,
            Err(NoSessionError)
        ));

        pair.side(Side::B).handle.connect();
        assert_no_status_for(
            &pair.side(Side::B).status,
            None,
            PeerStatus::Initiator,
            Duration::from_millis(150),
        )
        .await;
        assert_no_status_for(
            &pair.side(Side::B).status,
            None,
            PeerStatus::Connected,
            Duration::from_millis(150),
        )
        .await;
    })
    .await;
}

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
        let (platform_a, outbound_a, inbound_a_tx, status_a) = TestPlatform::new();
        let (platform_b, outbound_b, inbound_b_tx, status_b, inbound_b) =
            TestPlatform::new_with_inbound();
        let (identity_a, identity_b) = test_identities(&SoftwareCrypto);

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config_a);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config_b);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        let drop_flag = Arc::new(AtomicBool::new(false));
        spawn_forwarder(outbound_a, inbound_b_tx);
        spawn_gated_forwarder(outbound_b, inbound_a_tx, drop_flag.clone());

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect();

        await_status(&status_a, Some(identity_b.xid), PeerStatus::Connected).await;
        await_status(&status_b, Some(identity_a.xid), PeerStatus::Connected).await;

        let responder_task = tokio::task::spawn_local(async move {
            let stream = inbound_b.recv().await.unwrap();
            let _ = read_all(stream.reader).await;
            let err = stream.writer.finish().await.unwrap_err();
            assert!(matches!(err, QlStreamError::NoSession));
        });

        drop_flag.store(true, Ordering::Relaxed);

        let mut pending = handle_a.open_stream(test_route_id()).await.unwrap();
        let err = pending.writer.finish().await.unwrap_err();
        assert!(matches!(err, QlStreamError::NoSession));

        await_status(&status_a, Some(identity_b.xid), PeerStatus::Disconnected).await;

        let result =
            tokio::time::timeout(Duration::from_millis(300), next_chunk(&mut pending.reader))
                .await
                .unwrap();
        assert!(matches!(result, Err(QlStreamError::NoSession)));

        responder_task.abort();
    })
    .await;
}
