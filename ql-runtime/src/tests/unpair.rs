use super::*;

#[tokio::test(flavor = "current_thread")]
async fn unpair_clears_remote_peer_and_aborts_active_stream() {
    run_local_test(async {
        let config = default_runtime_config();
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = TestPlatform::new_with_inbound(2);
        let identity_a = new_identity(11);
        let identity_b = new_identity(73);

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect().unwrap();

        await_status(&status_a, identity_b.xid, PeerStage::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStage::Connected).await;

        let responder = tokio::task::spawn_local(async move {
            let stream = inbound_b.recv().await.unwrap();
            let mut request = stream.request;
            let _ = request.next_chunk().await;
            let second = request.next_chunk().await;
            assert!(matches!(second, Ok(None) | Err(QlError::Cancelled)));
        });

        let mut stream = handle_a.open_stream().await.unwrap();
        stream.request.write_all(&[1, 2, 3, 4]).await.unwrap();

        handle_a.unpair().unwrap();
        assert!(matches!(
            handle_a.open_stream().await,
            Err(QlError::NoPeerBound)
        ));

        tokio::time::timeout(std::time::Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();

        let open_err_b = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match handle_b.open_stream().await {
                    Err(QlError::NoPeerBound) => return,
                    _ => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
                }
            }
        })
        .await;
        assert!(open_err_b.is_ok(), "remote peer was not cleared");
    })
    .await;
}
