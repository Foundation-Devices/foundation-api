use std::time::Duration;

use bytes::Bytes;
use ql_wire::StreamCloseCode;

use super::*;
use crate::QlStreamError;

#[tokio::test(flavor = "current_thread")]
async fn open_stream_duplex_happy_path() {
    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();

            let mut writer = inbound.writer;
            let mut reader = inbound.reader;

            assert_eq!(next_chunk(&mut reader).await.unwrap(), Some(vec![1, 2]));
            writer.write(Bytes::from_static(&[9])).await.unwrap();
            assert_eq!(next_chunk(&mut reader).await.unwrap(), Some(vec![3, 4]));
            writer.write(Bytes::from_static(&[8, 7])).await.unwrap();
            assert_eq!(next_chunk(&mut reader).await.unwrap(), None);
            writer.finish().await.unwrap();
        });

        let mut stream = pair
            .side(Side::A)
            .handle
            .open_stream(test_route_id())
            .await
            .unwrap();
        stream
            .writer
            .write(Bytes::from_static(&[1, 2]))
            .await
            .unwrap();
        assert_eq!(next_chunk(&mut stream.reader).await.unwrap(), Some(vec![9]));
        stream
            .writer
            .write(Bytes::from_static(&[3, 4]))
            .await
            .unwrap();
        stream.writer.finish().await.unwrap();
        assert_eq!(
            next_chunk(&mut stream.reader).await.unwrap(),
            Some(vec![8, 7])
        );
        assert_eq!(next_chunk(&mut stream.reader).await.unwrap(), None);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn reader_respects_max_len() {
    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);

        let responder = tokio::task::spawn_local(async move {
            let inbound = inbound_b.recv().await.unwrap();
            let mut reader = inbound.reader;

            assert_eq!(next_chunk_max(&mut reader, 2).await.unwrap(), Some(vec![1, 2]));
            assert_eq!(
                next_chunk_max(&mut reader, 2).await.unwrap(),
                Some(vec![3, 4])
            );
            assert_eq!(next_chunk_max(&mut reader, 2).await.unwrap(), Some(vec![5, 6]));
            assert_eq!(next_chunk(&mut reader).await.unwrap(), None);

            inbound.writer.finish().await.unwrap();
        });

        let mut stream = pair
            .side(Side::A)
            .handle
            .open_stream(test_route_id())
            .await
            .unwrap();
        stream
            .writer
            .write(Bytes::from_static(&[1, 2, 3, 4, 5, 6]))
            .await
            .unwrap();
        stream.writer.finish().await.unwrap();
        assert_eq!(next_chunk(&mut stream.reader).await.unwrap(), None);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn large_stream_payload_round_trips() {
    run_local_test(async {
        let payload: Vec<u8> = (0..40).collect();
        let mut pair = TestPair::new(default_runtime_config());
        let (done_tx, done_rx) = async_channel::bounded(1);
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);

        let responder = tokio::task::spawn_local(async move {
            let stream = inbound_b.recv().await.unwrap();
            let request_data = read_all(stream.reader).await.unwrap();
            stream.writer.finish().await.unwrap();
            done_tx.send(request_data).await.unwrap();
        });

        let mut stream = pair
            .side(Side::A)
            .handle
            .open_stream(test_route_id())
            .await
            .unwrap();
        stream
            .writer
            .write(Bytes::from(payload.clone()))
            .await
            .unwrap();
        stream.writer.finish().await.unwrap();
        assert_eq!(next_chunk(&mut stream.reader).await.unwrap(), None);

        let received = tokio::time::timeout(Duration::from_secs(2), done_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, payload);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_responder_closes_initiator_response() {
    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);

        let responder = tokio::task::spawn_local(async move {
            let stream = inbound_b.recv().await.unwrap();
            drop(stream.reader);
        });

        let mut stream = pair
            .side(Side::A)
            .handle
            .open_stream(test_route_id())
            .await
            .unwrap();
        let err = stream.writer.finish().await.unwrap_err();
        assert!(matches!(
            err,
            QlStreamError::StreamClosed { code } if code == StreamCloseCode::CANCELLED
        ));

        let err = next_chunk(&mut stream.reader).await.unwrap_err();
        assert!(matches!(
            err,
            QlStreamError::StreamClosed { code } if code == StreamCloseCode::CANCELLED
        ));

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_inbound_reader_cancels_remote_writer() {
    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        let inbound_b = pair.take_inbound(Side::B);
        let (go_tx, go_rx) = async_channel::bounded(1);
        pair.connect_and_wait(Side::A).await;

        let responder = tokio::task::spawn_local(async move {
            let stream = inbound_b.recv().await.unwrap();
            let mut writer = stream.writer;
            let mut reader = stream.reader;
            assert_eq!(next_chunk(&mut reader).await.unwrap(), None);
            writer
                .write(Bytes::from_static(&[1, 2, 3, 4]))
                .await
                .unwrap();
            go_rx.recv().await.unwrap();
            let _ = writer.write(Bytes::from(vec![5; 64])).await;
            let err = writer.finish().await.unwrap_err();
            assert!(matches!(
                err,
                QlStreamError::StreamClosed { code } if code == StreamCloseCode::CANCELLED
            ));
        });

        let mut stream = pair
            .side(Side::A)
            .handle
            .open_stream(test_route_id())
            .await
            .unwrap();
        stream.writer.finish().await.unwrap();
        assert_eq!(
            next_chunk(&mut stream.reader).await.unwrap(),
            Some(vec![1, 2, 3, 4])
        );
        drop(stream.reader);
        go_tx.send(()).await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn closing_initiator_reader_preserves_initiator_writer() {
    run_local_test(async {
        let mut pair = TestPair::new(default_runtime_config());
        pair.connect_and_wait(Side::A).await;
        let inbound_b = pair.take_inbound(Side::B);
        let (done_tx, done_rx) = async_channel::bounded(1);

        let responder = tokio::task::spawn_local(async move {
            let stream = inbound_b.recv().await.unwrap();
            let request = read_all(stream.reader).await.unwrap();
            done_tx.send(request).await.unwrap();
        });

        let stream = pair
            .side(Side::A)
            .handle
            .open_stream(test_route_id())
            .await
            .unwrap();
        let mut writer = stream.writer;
        stream.reader.close(StreamCloseCode::CANCELLED);

        writer.write(Bytes::from_static(&[1, 2])).await.unwrap();
        writer.write(Bytes::from_static(&[3, 4])).await.unwrap();
        writer.finish().await.unwrap();

        let request = tokio::time::timeout(Duration::from_secs(2), done_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request, vec![1, 2, 3, 4]);

        tokio::time::timeout(Duration::from_secs(2), responder)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn max_concurrent_message_writes_is_respected() {
    run_local_test(async {
        let stats = WriteStats::new();
        let config = RuntimeConfig {
            max_concurrent_message_writes: 2,
            ..default_runtime_config()
        };
        let (platform_a, outbound_a, status_a) =
            TestPlatform::new_with_delayed_writes(Duration::from_millis(40), stats.clone());
        let (platform_b, outbound_b, status_b, inbound_b) = TestPlatform::new_with_inbound();
        let (identity_a, identity_b) = test_identities(&SoftwareCrypto);

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_forwarder(outbound_a, handle_b.clone());
        spawn_forwarder(outbound_b, handle_a.clone());

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect();

        await_status(&status_a, identity_b.xid, PeerStatus::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStatus::Connected).await;

        let responder = tokio::task::spawn_local(async move {
            for _ in 0..4 {
                let stream = inbound_b.recv().await.unwrap();
                let _ = read_all(stream.reader).await;
                let mut writer = stream.writer;
                writer.queue_finish();
            }
        });

        let mut tasks = Vec::new();
        for i in 0..4u8 {
            let handle = handle_a.clone();
            tasks.push(tokio::task::spawn_local(async move {
                let mut stream = handle.open_stream(test_route_id()).await.unwrap();
                stream.writer.write(Bytes::from(vec![i; 8])).await.unwrap();
                stream.writer.finish().await.unwrap();
                assert_eq!(next_chunk(&mut stream.reader).await.unwrap(), None);
            }));
        }

        for task in tasks {
            tokio::time::timeout(Duration::from_secs(4), task)
                .await
                .unwrap()
                .unwrap();
        }

        tokio::time::timeout(Duration::from_secs(4), responder)
            .await
            .unwrap()
            .unwrap();

        assert!(
            stats.max_active() <= 2,
            "max active writes exceeded: {}",
            stats.max_active()
        );
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn stream_round_trip_survives_encrypted_packet_drops() {
    run_local_test(async {
        let config = RuntimeConfig {
            fsm: QlFsmConfig {
                session_record_retransmit_timeout: Duration::from_millis(20),
                ..default_runtime_config().fsm
            },
            ..default_runtime_config()
        };
        let (platform_a, outbound_a, status_a) = TestPlatform::new();
        let (platform_b, outbound_b, status_b, inbound_b) = TestPlatform::new_with_inbound();
        let (identity_a, identity_b) = test_identities(&SoftwareCrypto);

        let request_payload: Vec<u8> = (0..32).collect();
        let response_payload: Vec<u8> = (100..132).collect();
        let expected_response = response_payload.clone();

        let (runtime_a, handle_a) = new_runtime(identity_a.clone(), platform_a, config);
        let (runtime_b, handle_b) = new_runtime(identity_b.clone(), platform_b, config);

        tokio::task::spawn_local(async move { runtime_a.run().await });
        tokio::task::spawn_local(async move { runtime_b.run().await });

        spawn_drop_every_nth_encrypted_forwarder(outbound_a, handle_b.clone(), 3);
        spawn_drop_every_nth_encrypted_forwarder(outbound_b, handle_a.clone(), 3);

        register_peers(&handle_a, &handle_b, &identity_a, &identity_b);
        handle_a.connect();

        await_status(&status_a, identity_b.xid, PeerStatus::Connected).await;
        await_status(&status_b, identity_a.xid, PeerStatus::Connected).await;

        let responder = tokio::task::spawn_local(async move {
            let stream = inbound_b.recv().await.unwrap();
            let received_request = read_all(stream.reader).await.unwrap();
            let mut writer = stream.writer;
            writer
                .write(Bytes::from(response_payload.clone()))
                .await
                .unwrap();
            writer.finish().await.unwrap();
            received_request
        });

        let mut stream = handle_a.open_stream(test_route_id()).await.unwrap();
        stream
            .writer
            .write(Bytes::from(request_payload.clone()))
            .await
            .unwrap();
        stream.writer.finish().await.unwrap();

        let mut received_response = Vec::new();
        while let Some(chunk) = next_chunk(&mut stream.reader).await.unwrap() {
            received_response.extend_from_slice(&chunk);
        }
        assert_eq!(received_response, expected_response);

        let received_request = tokio::time::timeout(Duration::from_secs(4), responder)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received_request, request_payload);
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn multi_megabyte_stream_survives_asymmetric_loss_and_delay() {
    run_local_test_timeout(Duration::from_secs(5), async {
        let payload_len = 2 * 1024 * 1024;
        let chunk_len = 16 * 1024;
        let payload: Vec<u8> = (0..payload_len)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let expected = payload.clone();
        let config = RuntimeConfig {
            fsm: QlFsmConfig {
                session_record_max_size: 16 * 1024,
                session_record_ack_delay: Duration::from_millis(2),
                session_record_retransmit_timeout: Duration::from_millis(25),
                session_stream_send_buffer_size: 4 * 1024 * 1024,
                session_stream_receive_buffer_size: 4 * 1024 * 1024,
                session_accepted_record_window: 16 * 1024,
                session_pending_ack_range_limit: 4 * 1024,
                ..default_runtime_config().fsm
            },
            stream_send_buffer_bytes: 4 * 1024 * 1024,
            ..default_runtime_config()
        };
        let (mut pair, links) = TestPair::new_with_controlled_links(
            config,
            LinkBehavior {
                base_delay: Duration::from_millis(1),
                drop_encrypted_every: Some(41),
                delay_encrypted_every: Some((13, Duration::from_millis(12))),
                ..LinkBehavior::default()
            },
            LinkBehavior {
                base_delay: Duration::from_millis(1),
                ..LinkBehavior::default()
            },
        );
        pair.connect_and_wait(Side::A).await;
        links.b_to_a.store(LinkBehavior {
            base_delay: Duration::from_millis(3),
            drop_encrypted_every: Some(7),
            duplicate_encrypted_every: Some(19),
            delay_encrypted_every: Some((3, Duration::from_millis(25))),
        });
        let inbound_b = pair.take_inbound(Side::B);

        let responder = tokio::task::spawn_local(async move {
            let stream = inbound_b.recv().await.unwrap();
            eprintln!("responder accepted inbound stream");
            let mut reader = stream.reader;
            let mut received = Vec::new();
            while let Some(chunk) = next_chunk(&mut reader).await.unwrap() {
                if received.len() >= 36 * chunk_len {
                    eprintln!("responder received chunk of {} bytes", chunk.len());
                }
                received.extend_from_slice(&chunk);
                if received.len() % (256 * 1024) == 0 {
                    eprintln!("responder received {} bytes", received.len());
                }
            }
            stream.writer.finish().await.unwrap();
            received
        });

        let recovery_links = links.clone();
        let recovery = tokio::task::spawn_local(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            eprintln!("restoring reverse path");
            recovery_links.b_to_a.store(LinkBehavior {
                base_delay: Duration::from_millis(1),
                delay_encrypted_every: Some((17, Duration::from_millis(8))),
                ..LinkBehavior::default()
            });
        });

        let writer = tokio::task::spawn_local(async move {
            let mut stream = pair
                .side(Side::A)
                .handle
                .open_stream(test_route_id())
                .await
                .unwrap();
            for (index, chunk) in payload.chunks(chunk_len).enumerate() {
                if index + 1 >= 40 {
                    eprintln!("writer attempting chunk {}", index + 1);
                }
                stream
                    .writer
                    .write(Bytes::copy_from_slice(chunk))
                    .await
                    .unwrap();
                if index + 1 >= 40 {
                    eprintln!("writer queued chunk {}", index + 1);
                }
                if index % 16 == 15 {
                    eprintln!("writer queued {} chunks", index + 1);
                }
            }
            eprintln!("writer finished queueing");
            stream.writer.finish().await.unwrap();
            eprintln!("writer waiting for eof");
            assert_eq!(next_chunk(&mut stream.reader).await.unwrap(), None);
            eprintln!("writer observed eof");
        });

        tokio::time::timeout(Duration::from_secs(30), writer)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), recovery)
            .await
            .unwrap()
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(30), responder)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, expected);
    })
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn reproducer_writer_stalls_after_reverse_path_impairment() {
    run_local_test_timeout(Duration::from_secs(5), async {
        let payload_len = 2 * 1024 * 1024;
        let chunk_len = 16 * 1024;
        let payload: Vec<u8> = (0..payload_len)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let config = RuntimeConfig {
            fsm: QlFsmConfig {
                session_record_max_size: 16 * 1024,
                session_record_ack_delay: Duration::from_millis(2),
                session_record_retransmit_timeout: Duration::from_millis(25),
                session_stream_send_buffer_size: 4 * 1024 * 1024,
                session_stream_receive_buffer_size: 4 * 1024 * 1024,
                session_accepted_record_window: 16 * 1024,
                session_pending_ack_range_limit: 4 * 1024,
                ..default_runtime_config().fsm
            },
            stream_send_buffer_bytes: 4 * 1024 * 1024,
            ..default_runtime_config()
        };
        let (mut pair, links) = TestPair::new_with_controlled_links(
            config,
            LinkBehavior {
                base_delay: Duration::from_millis(1),
                drop_encrypted_every: Some(41),
                delay_encrypted_every: Some((13, Duration::from_millis(12))),
                ..LinkBehavior::default()
            },
            LinkBehavior {
                base_delay: Duration::from_millis(1),
                ..LinkBehavior::default()
            },
        );
        pair.connect_and_wait(Side::A).await;
        links.b_to_a.store(LinkBehavior {
            base_delay: Duration::from_millis(3),
            drop_encrypted_every: Some(7),
            duplicate_encrypted_every: Some(19),
            delay_encrypted_every: Some((3, Duration::from_millis(25))),
        });
        let inbound_b = pair.take_inbound(Side::B);

        let responder = tokio::task::spawn_local(async move {
            let stream = inbound_b.recv().await.unwrap();
            let mut reader = stream.reader;
            let mut received = Vec::new();
            while let Some(chunk) = next_chunk(&mut reader).await.unwrap() {
                received.extend_from_slice(&chunk);
            }
        });

        let recovery_links = links.clone();
        let recovery = tokio::task::spawn_local(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            recovery_links.b_to_a.store(LinkBehavior {
                base_delay: Duration::from_millis(1),
                delay_encrypted_every: Some((17, Duration::from_millis(8))),
                ..LinkBehavior::default()
            });
        });

        let writer = tokio::task::spawn_local(async move {
            let mut stream = pair
                .side(Side::A)
                .handle
                .open_stream(test_route_id())
                .await
                .unwrap();
            for chunk in payload.chunks(chunk_len) {
                stream
                    .writer
                    .write(Bytes::copy_from_slice(chunk))
                    .await
                    .unwrap();
            }
            stream.writer.queue_finish();
            let _ = next_chunk(&mut stream.reader).await;
        });

        let _ = tokio::time::timeout(Duration::from_secs(15), writer).await;
        recovery.abort();
        responder.abort();
    })
    .await;
}
