use super::*;

#[test]
fn replayed_unpair_is_ignored_after_rebind() {
    let config = EngineConfig::default();
    let SingleEngineHarness {
        now,
        mut engine,
        peer,
        session_key: _session_key,
    } = SingleEngineHarness::connected(config, 111, 5);
    let peer_b = peer_from_identity(&peer);
    let bytes = wire::encode_record(&wire::unpair::build_unpair_record(
        &peer,
        QlHeader {
            sender: peer.xid,
            recipient: engine.engine.identity.xid,
        },
        wire::ControlMeta {
            packet_id: PacketId(9),
            valid_until: wire::now_secs().saturating_add(60),
        },
    ));

    let first = engine.run_tick_collect(now, EngineInput::Incoming(bytes.clone()));
    assert!(first
        .iter()
        .any(|output| matches!(output, EngineOutput::ClearPeer)));
    assert!(engine.peer.is_none());

    let _ = engine.run_tick_collect(now, EngineInput::BindPeer(peer_b.clone()));
    assert!(engine.peer.is_some());

    let second = engine.run_tick_collect(now, EngineInput::Incoming(bytes));
    assert!(!second
        .iter()
        .any(|output| matches!(output, EngineOutput::ClearPeer)));
    assert_eq!(
        engine.peer.as_ref().map(|peer| peer.peer),
        Some(peer_b.peer)
    );
}
