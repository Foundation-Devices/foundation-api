use std::time::Duration;

use ql_wire::QlRecord;

use super::*;
use crate::{state::LinkState, QlFsmError};

#[test]
fn ik_connect_round_trip_establishes_transport() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());

    harness
        .a
        .fsm
        .connect_ik(harness.time(), &harness.a.crypto)
        .unwrap();
    harness.pump();

    assert!(matches!(harness.a.fsm.state.link, LinkState::Connected(_)));
    assert!(matches!(harness.b.fsm.state.link, LinkState::Connected(_)));
}

#[test]
fn kk_connect_round_trip_establishes_transport() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());

    harness
        .a
        .fsm
        .connect_kk(harness.time(), &harness.a.crypto)
        .unwrap();
    harness.pump();

    assert!(matches!(harness.a.fsm.state.link, LinkState::Connected(_)));
    assert!(matches!(harness.b.fsm.state.link, LinkState::Connected(_)));
}

#[test]
fn connect_methods_require_bound_peer() {
    let time = Harness::paired_known(QlFsmConfig::default()).time();
    let identity = test_identity(55);
    let mut fsm = QlFsm::new(QlFsmConfig::default(), identity, time);
    let crypto = TestCrypto::new(9);

    assert_eq!(fsm.connect_ik(time, &crypto), Err(QlFsmError::NoPeerBound));
    assert_eq!(fsm.connect_kk(time, &crypto), Err(QlFsmError::NoPeerBound));
}

#[test]
fn connect_methods_return_busy_when_link_is_not_idle() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());

    harness
        .a
        .fsm
        .connect_ik(harness.time(), &harness.a.crypto)
        .unwrap();

    assert_eq!(
        harness.a.fsm.connect_ik(harness.time(), &harness.a.crypto),
        Err(QlFsmError::Busy)
    );
    assert_eq!(
        harness.a.fsm.connect_kk(harness.time(), &harness.a.crypto),
        Err(QlFsmError::Busy)
    );
}

#[test]
fn inbound_ik1_auto_binds_unbound_responder() {
    let mut harness = Harness::paired(QlFsmConfig::default(), true, false);

    harness
        .a
        .fsm
        .connect_ik(harness.time(), &harness.a.crypto)
        .unwrap();
    harness.pump();

    assert_eq!(
        harness.b.fsm.state.peer,
        Some(harness.a.fsm.identity.bundle())
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

    harness
        .a
        .fsm
        .connect_ik(harness.time(), &harness.a.crypto)
        .unwrap();
    let first = harness.next_outbound_a().unwrap();
    assert!(matches!(
        first,
        QlRecord::Handshake(ql_wire::QlHandshakeRecord::Ik1(_))
    ));
    assert!(harness.next_outbound_a().is_none());

    harness.advance(config.handshake_timeout);
    harness.a.fsm.on_timer(harness.time());

    assert!(matches!(harness.a.fsm.state.link, LinkState::Idle));
    assert!(harness.next_outbound_a().is_none());
}

#[test]
fn handshake_timeout_clears_queued_kk_output() {
    let config = QlFsmConfig {
        handshake_timeout: Duration::from_millis(60),
        ..QlFsmConfig::default()
    };
    let mut harness = Harness::paired_known(config);

    harness
        .a
        .fsm
        .connect_kk(harness.time(), &harness.a.crypto)
        .unwrap();

    harness.advance(config.handshake_timeout);
    harness.a.fsm.on_timer(harness.time());

    assert!(matches!(harness.a.fsm.state.link, LinkState::Idle));
    assert!(harness.next_outbound_a().is_none());
}

#[test]
fn bind_peer_clears_queued_handshake_output() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());

    harness
        .a
        .fsm
        .connect_ik(harness.time(), &harness.a.crypto)
        .unwrap();
    harness.a.fsm.bind_peer(test_identity(99).bundle());

    assert!(harness.next_outbound_a().is_none());
}

#[test]
fn simultaneous_ik_connect_converges() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());

    harness
        .a
        .fsm
        .connect_ik(harness.time(), &harness.a.crypto)
        .unwrap();
    harness
        .b
        .fsm
        .connect_ik(harness.time(), &harness.b.crypto)
        .unwrap();
    harness.pump();

    assert!(matches!(harness.a.fsm.state.link, LinkState::Connected(_)));
    assert!(matches!(harness.b.fsm.state.link, LinkState::Connected(_)));
}

#[test]
fn simultaneous_ik_and_kk_connect_prefers_ik() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());

    harness
        .a
        .fsm
        .connect_ik(harness.time(), &harness.a.crypto)
        .unwrap();
    harness
        .b
        .fsm
        .connect_kk(harness.time(), &harness.b.crypto)
        .unwrap();
    harness.pump();

    assert!(matches!(harness.a.fsm.state.link, LinkState::Connected(_)));
    assert!(matches!(harness.b.fsm.state.link, LinkState::Connected(_)));
}
