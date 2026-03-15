use super::*;

#[tokio::test(flavor = "current_thread")]
async fn unpair_aborts_active_stream_and_clears_peer() {
    run_local_test(async {
        let config = default_runtime_config();
        let (platform_a, outbound_a, status_a) = TestPlatform::new(1);
        let (platform_b, outbound_b, status_b, inbound_b) = TestPlatform::new_with_inbound(2);
        let identity_a = new_identity();
        let identity_b = new_identity();

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
            let stream = match inbound_b.recv().await.unwrap() {
                HandlerEvent::Stream(stream) => stream,
            };
            let mut request = stream.request;
            let _response = stream.respond_to.accept(Vec::new()).unwrap();
            let first = request.next_chunk().await;
            assert!(matches!(first, Ok(Some(_)) | Ok(None) | Err(_)));
            let second = request.next_chunk().await;
            assert!(matches!(
                second,
                Ok(None)
                    | Err(QlError::Cancelled)
                    | Err(QlError::SendFailed)
                    | Err(QlError::StreamReset { .. })
                    | Err(QlError::StreamProtocol)
            ));
        });

        let mut stream = handle_a
            .open_stream(Vec::new(), crate::runtime::StreamConfig::default())
            .await
            .unwrap();
        stream.inbound.write_all(&[1, 2, 3, 4]).await.unwrap();

        handle_a.unpair().unwrap();

        await_status(&status_a, identity_b.xid, PeerStage::Disconnected).await;
        await_status(&status_b, identity_a.xid, PeerStage::Disconnected).await;

        let write_err = stream.inbound.write_all(&[5, 6, 7, 8]).await.unwrap_err();
        assert!(matches!(write_err, QlError::Cancelled));

        let open_err_a = handle_a
            .open_stream(Vec::new(), crate::runtime::StreamConfig::default())
            .await;
        let open_err_b = handle_b
            .open_stream(Vec::new(), crate::runtime::StreamConfig::default())
            .await;

        assert!(matches!(open_err_a, Err(QlError::NoPeerBound)));
        assert!(matches!(open_err_b, Err(QlError::NoPeerBound)));

        tokio::time::timeout(std::time::Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}
