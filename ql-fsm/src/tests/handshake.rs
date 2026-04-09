use std::time::Duration;

use ql_wire::QlHandshakeRecord;

use super::*;
use crate::{state::LinkState, NoPeerError, PeerStatus, QlFsmEvent};

#[test]
fn ik_connect_round_trip_establishes_transport() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());

    harness.connect_ik_a().unwrap();
    harness.pump();

    assert!(matches!(harness.a.fsm.state.link, LinkState::Connected(_)));
    assert!(matches!(harness.b.fsm.state.link, LinkState::Connected(_)));
}

#[test]
fn kk_connect_round_trip_establishes_transport() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());

    harness.connect_kk_a().unwrap();
    harness.pump();

    assert!(matches!(harness.a.fsm.state.link, LinkState::Connected(_)));
    assert!(matches!(harness.b.fsm.state.link, LinkState::Connected(_)));
}

#[test]
fn xx_connect_round_trip_establishes_transport_when_armed() {
    let mut harness = Harness::paired(QlFsmConfig::default(), false, false);
    let token = pairing_token(1);

    harness.b.fsm.arm_pairing(token);
    harness.connect_xx_a(token);

    let xx1 = harness.next_outbound_a().unwrap();
    harness.deliver_to_b(xx1);
    let xx2 = harness.next_outbound_b().unwrap();
    harness.deliver_to_a(xx2);
    let xx3 = harness.next_outbound_a().unwrap();
    harness.deliver_to_b(xx3);

    let xx4 = harness.next_outbound_b().unwrap();
    harness.deliver_to_a(xx4);

    assert_eq!(harness.a.fsm.peer(), Some(&harness.b.fsm.identity.bundle()));
    assert_eq!(harness.b.fsm.peer(), Some(&harness.a.fsm.identity.bundle()));
    assert!(matches!(harness.a.fsm.state.link, LinkState::Connected(_)));
    assert!(matches!(harness.b.fsm.state.link, LinkState::Connected(_)));
}

#[test]
fn ik_connect_learns_remote_initial_stream_receive_window() {
    let mut harness = Harness::paired_known_with_configs(
        QlFsmConfig {
            session_stream_receive_buffer_size: 9,
            ..QlFsmConfig::default()
        },
        QlFsmConfig {
            session_stream_receive_buffer_size: 3,
            ..QlFsmConfig::default()
        },
    );

    harness.connect_ik_a().unwrap();
    harness.pump();

    assert_eq!(
        harness
            .a
            .fsm
            .state
            .link
            .transport()
            .unwrap()
            .remote_transport_params
            .initial_stream_receive_window,
        3
    );
    assert_eq!(
        harness
            .b
            .fsm
            .state
            .link
            .transport()
            .unwrap()
            .remote_transport_params
            .initial_stream_receive_window,
        9
    );
}

#[test]
fn connect_methods_require_bound_peer() {
    let time = Harness::paired_known(QlFsmConfig::default()).time();
    let identity = test_identity(&SoftwareCrypto);
    let mut fsm = QlFsm::new(QlFsmConfig::default(), identity, time);
    let crypto = SoftwareCrypto;

    assert_eq!(fsm.connect_ik(time, &crypto), Err(NoPeerError));
    assert_eq!(fsm.connect_kk(time, &crypto), Err(NoPeerError));

    fsm.connect_xx(time, pairing_token(2), &crypto);
}

#[test]
fn connect_ik_emits_initiator_status() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());

    harness.connect_ik_a().unwrap();

    assert_eq!(
        harness.drain_events_a(),
        vec![QlFsmEvent::PeerStatusChanged(PeerStatus::Initiator)]
    );
}

#[test]
fn inbound_xx1_ignored_when_pairing_token_not_armed() {
    let mut harness = Harness::paired(QlFsmConfig::default(), false, false);
    let token = pairing_token(3);

    harness.connect_xx_a(token);
    let xx1 = harness.next_outbound_a().unwrap();
    harness.deliver_to_b(xx1);

    assert!(matches!(harness.b.fsm.state.link, LinkState::Idle));
    assert!(harness.drain_events_b().is_empty());
    assert!(harness.next_outbound_b().is_none());
}

#[test]
fn disarm_pairing_rejects_inflight_inbound_xx_responder() {
    let mut harness = Harness::paired(QlFsmConfig::default(), false, false);
    let token = pairing_token(5);

    harness.b.fsm.arm_pairing(token);
    harness.connect_xx_a(token);
    let xx1 = harness.next_outbound_a().unwrap();
    harness.deliver_to_b(xx1);
    let xx2 = harness.next_outbound_b().unwrap();
    harness.deliver_to_a(xx2);
    let xx3 = harness.next_outbound_a().unwrap();
    harness.b.fsm.disarm_pairing();
    harness.deliver_to_b(xx3);

    assert!(matches!(harness.b.fsm.state.link, LinkState::Idle));
    assert!(harness.next_outbound_b().is_none());
}

#[test]
fn simultaneous_xx_connect_converges() {
    let mut harness = Harness::paired(QlFsmConfig::default(), false, false);
    let token = pairing_token(6);

    harness.a.fsm.arm_pairing(token);
    harness.b.fsm.arm_pairing(token);
    harness.connect_xx_a(token);
    harness.connect_xx_b(token);

    for _ in 0..2 {
        if let Some(record) = harness.next_outbound_a() {
            harness.deliver_to_b(record);
        }
        if let Some(record) = harness.next_outbound_b() {
            harness.deliver_to_a(record);
        }
    }
    harness.pump();

    assert!(matches!(harness.a.fsm.state.link, LinkState::Connected(_)));
    assert!(matches!(harness.b.fsm.state.link, LinkState::Connected(_)));
}

#[test]
fn connect_ik_replaces_in_flight_attempt_and_ignores_stale_reply() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());

    harness.connect_ik_a().unwrap();
    harness.drain_events_a();
    let first = harness.next_outbound_a().unwrap();
    let first_id = handshake_id(&first);

    harness.connect_ik_a().unwrap();
    let second = harness.next_outbound_a().unwrap();
    let second_id = handshake_id(&second);

    assert_ne!(first_id, second_id);

    harness.deliver_to_b(first);
    let stale_reply = harness.next_outbound_b().unwrap();
    assert_eq!(handshake_id(&stale_reply), first_id);

    harness.deliver_to_a(stale_reply);
    assert!(matches!(
        harness.a.fsm.state.link,
        LinkState::IkInitiator(_)
    ));

    harness.deliver_to_b(second);
    harness.pump();

    assert!(matches!(harness.a.fsm.state.link, LinkState::Connected(_)));
    assert!(matches!(harness.b.fsm.state.link, LinkState::Connected(_)));
}

#[test]
fn connect_kk_replaces_in_flight_attempt_and_ignores_stale_reply() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());

    harness.connect_kk_a().unwrap();
    let first = harness.next_outbound_a().unwrap();
    let first_id = handshake_id(&first);

    harness.connect_kk_a().unwrap();
    let second = harness.next_outbound_a().unwrap();
    let second_id = handshake_id(&second);

    assert_ne!(first_id, second_id);

    harness.deliver_to_b(first);
    let stale_reply = harness.next_outbound_b().unwrap();
    assert_eq!(handshake_id(&stale_reply), first_id);

    harness.deliver_to_a(stale_reply);
    assert!(matches!(
        harness.a.fsm.state.link,
        LinkState::KkInitiator(_)
    ));

    harness.deliver_to_b(second);
    harness.pump();

    assert!(matches!(harness.a.fsm.state.link, LinkState::Connected(_)));
    assert!(matches!(harness.b.fsm.state.link, LinkState::Connected(_)));
}

#[test]
fn inbound_ik1_auto_binds_unbound_responder() {
    let mut harness = Harness::paired(QlFsmConfig::default(), true, false);

    harness.connect_ik_a().unwrap();
    harness.pump();

    let expected_peer = harness.a.fsm.identity.bundle();
    assert_eq!(harness.b.fsm.peer(), Some(&expected_peer));
    assert_eq!(
        harness.drain_events_b(),
        vec![
            QlFsmEvent::NewPeer,
            QlFsmEvent::PeerStatusChanged(PeerStatus::Connected),
        ]
    );
    assert!(matches!(harness.a.fsm.state.link, LinkState::Connected(_)));
    assert!(matches!(harness.b.fsm.state.link, LinkState::Connected(_)));
}

#[test]
fn handshake_timeout_drops_single_ik_attempt_without_resend() {
    let config = QlFsmConfig {
        handshake_timeout: Duration::from_millis(60),
        ..QlFsmConfig::default()
    };
    let mut harness = Harness::paired_known(config);

    harness.connect_ik_a().unwrap();
    harness.drain_events_a();
    let first = harness.next_outbound_a().unwrap();
    let (_, first) = ql_wire::decode_record::<QlHandshakeRecord, _>(first.as_slice()).unwrap();
    assert!(matches!(first, ql_wire::QlHandshakeRecord::Ik1(_)));
    assert!(harness.next_outbound_a().is_none());

    harness.advance(config.handshake_timeout);
    harness.on_timer_a();

    assert!(matches!(harness.a.fsm.state.link, LinkState::Idle));
    assert_eq!(
        harness.take_event_a(),
        Some(QlFsmEvent::PeerStatusChanged(PeerStatus::Disconnected))
    );
    assert!(harness.next_outbound_a().is_none());
}

#[test]
fn handshake_timeout_clears_queued_kk_output() {
    let config = QlFsmConfig {
        handshake_timeout: Duration::from_millis(60),
        ..QlFsmConfig::default()
    };
    let mut harness = Harness::paired_known(config);

    harness.connect_kk_a().unwrap();

    harness.advance(config.handshake_timeout);
    harness.on_timer_a();

    assert!(matches!(harness.a.fsm.state.link, LinkState::Idle));
    assert!(harness.next_outbound_a().is_none());
}

#[test]
fn bind_peer_clears_queued_handshake_output() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());

    harness.connect_ik_a().unwrap();
    harness.drain_events_a();
    harness
        .a
        .fsm
        .bind_peer(test_identity(&SoftwareCrypto).bundle());

    assert!(harness.drain_events_a().is_empty());
    assert!(harness.next_outbound_a().is_none());
}

#[test]
fn simultaneous_ik_connect_converges() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());

    harness.connect_ik_a().unwrap();
    harness.connect_ik_b().unwrap();
    harness.pump();

    assert!(matches!(harness.a.fsm.state.link, LinkState::Connected(_)));
    assert!(matches!(harness.b.fsm.state.link, LinkState::Connected(_)));
}

#[test]
fn simultaneous_ik_and_kk_connect_prefers_ik() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());

    harness.connect_ik_a().unwrap();
    harness.connect_kk_b().unwrap();
    harness.pump();

    assert!(matches!(harness.a.fsm.state.link, LinkState::Connected(_)));
    assert!(matches!(harness.b.fsm.state.link, LinkState::Connected(_)));
}

fn handshake_id(record: &[u8]) -> ql_wire::HandshakeId {
    let (_, record) = ql_wire::decode_record(record).unwrap();
    match record {
        ql_wire::QlHandshakeRecord::Ik1(message) => message.meta.handshake_id,
        ql_wire::QlHandshakeRecord::Ik2(message) => message.meta.handshake_id,
        ql_wire::QlHandshakeRecord::Kk1(message) => message.meta.handshake_id,
        ql_wire::QlHandshakeRecord::Kk2(message) => message.meta.handshake_id,
        ql_wire::QlHandshakeRecord::Xx1(message) => message.meta.handshake_id,
        ql_wire::QlHandshakeRecord::Xx2(message) => message.meta.handshake_id,
        ql_wire::QlHandshakeRecord::Xx3(message) => message.meta.handshake_id,
        ql_wire::QlHandshakeRecord::Xx4(message) => message.meta.handshake_id,
    }
}
