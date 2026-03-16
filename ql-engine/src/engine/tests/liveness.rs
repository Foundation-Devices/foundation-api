use super::*;

#[test]
fn replayed_heartbeat_is_ignored() {
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(EngineConfig::default(), 101, 4);
    let heartbeat = wire::heartbeat::encrypt_heartbeat(
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
        },
        &session_key,
        wire::heartbeat::HeartbeatBody {
            meta: wire::ControlMeta {
                packet_id: PacketId(7),
                valid_until: wire::now_secs().saturating_add(60),
            },
        },
        [3; wire::encrypted_message::NONCE_SIZE],
    );
    let bytes = wire::encode_record(&heartbeat);

    let _first = engine.run_tick_collect(now, EngineInput::Incoming(bytes.clone()));
    let first_write = engine.take_next_write().unwrap();
    let first_record = wire::decode_record(&first_write.bytes).unwrap();
    assert!(matches!(first_record.payload, QlPayload::Heartbeat(_)));
    let _ = engine.complete_write_collect(first_write.id, Ok(()));

    let _second = engine.run_tick_collect(now, EngineInput::Incoming(bytes));
    assert!(engine.take_next_write().is_none());
}

#[test]
fn keepalive_deadline_is_derived_from_peer_state() {
    let mut config = EngineConfig::default();
    config.keep_alive = Some(KeepAliveConfig {
        interval: Duration::from_secs(5),
        timeout: Duration::from_secs(7),
    });
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key,
    } = SingleEngineHarness::connected(config, 103, 6);

    let heartbeat = encrypt_heartbeat_record(
        peer.xid,
        engine.engine.identity.xid,
        &session_key,
        1,
        [7; wire::encrypted_message::NONCE_SIZE],
    );
    let outputs =
        engine.run_tick_collect(now, EngineInput::Incoming(wire::encode_record(&heartbeat)));
    let _ = outputs;
    assert_eq!(engine.next_deadline(), Some(now + Duration::from_secs(5)));

    let write = engine.take_next_write().unwrap();
    let record = wire::decode_record(&write.bytes).unwrap();
    assert!(matches!(record.payload, QlPayload::Heartbeat(_)));
    let _ = engine.complete_write_collect(write.id, Ok(()));

    let outputs = engine.run_tick_collect(now + Duration::from_secs(5), EngineInput::TimerExpired);
    let _ = outputs;
    assert_eq!(engine.next_deadline(), Some(now + Duration::from_secs(12)));

    let write = engine.take_next_write().unwrap();
    let record = wire::decode_record(&write.bytes).unwrap();
    assert!(matches!(record.payload, QlPayload::Heartbeat(_)));
    let _ = engine.complete_write_collect(write.id, Ok(()));

    let outputs = engine.run_tick_collect(now + Duration::from_secs(12), EngineInput::TimerExpired);
    assert!(outputs.iter().any(|output| {
        matches!(
            output,
            EngineOutput::PeerStatusChanged {
                session: PeerSession::Disconnected,
                ..
            }
        )
    }));
}
