use std::time::Duration;

use ql_wire::{HandshakePayload, QlRecord};

use super::*;
use crate::state::ConnectionState;

#[test]
fn kk_connect_round_trip_establishes_transport() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    harness.pump();

    assert!(matches!(
        harness.a.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Connected(_))
    ));
    assert!(matches!(
        harness.b.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Connected(_))
    ));
}

#[test]
fn xx_connect_round_trip_learns_peer_bundles() {
    let mut harness = Harness::paired_unknown(QlFsmConfig::default());

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    harness.pump();

    assert_eq!(
        harness.a.fsm.peer.as_ref().unwrap().peer.bundle,
        Some(harness.b.fsm.identity.bundle())
    );
    assert_eq!(
        harness.b.fsm.peer.as_ref().unwrap().peer.bundle,
        Some(harness.a.fsm.identity.bundle())
    );
    assert!(matches!(
        harness.a.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Connected(_))
    ));
    assert!(matches!(
        harness.b.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Connected(_))
    ));
}

#[test]
fn inbound_xx1_auto_binds_unbound_responder() {
    let mut harness = Harness::responder_unbound_unknown(QlFsmConfig::default());

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    harness.pump();

    assert_eq!(
        harness.b.fsm.peer.as_ref().map(|entry| entry.peer.xid),
        Some(harness.a.fsm.identity.xid)
    );
    assert_eq!(
        harness.b.fsm.peer.as_ref().unwrap().peer.bundle,
        Some(harness.a.fsm.identity.bundle())
    );
}

#[test]
fn handshake_timeout_drops_single_attempt_without_resend() {
    let config = QlFsmConfig {
        handshake_timeout: Duration::from_millis(60),
        ..QlFsmConfig::default()
    };
    let mut harness = Harness::paired_unknown(config);

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    let first = harness.next_outbound_a().unwrap();
    assert!(matches!(
        first,
        QlRecord::Handshake(ql_wire::QlHandshakeRecord {
            payload: HandshakePayload::Xx1(_),
            ..
        })
    ));
    assert!(harness.next_outbound_a().is_none());

    harness.advance(config.handshake_timeout);
    harness.a.fsm.on_timer(harness.time());

    assert!(matches!(
        harness.a.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Disconnected)
    ));
    assert!(harness.next_outbound_a().is_none());
}

#[test]
fn handshake_timeout_clears_queued_handshake_output() {
    let config = QlFsmConfig {
        handshake_timeout: Duration::from_millis(60),
        ..QlFsmConfig::default()
    };
    let mut harness = Harness::paired_unknown(config);

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();

    harness.advance(config.handshake_timeout);
    harness.a.fsm.on_timer(harness.time());

    assert!(matches!(
        harness.a.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Disconnected)
    ));
    assert!(harness.next_outbound_a().is_none());
}

#[test]
fn bind_peer_clears_queued_handshake_output() {
    let mut harness = Harness::paired_unknown(QlFsmConfig::default());

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    harness.a.fsm.bind_peer(Peer {
        xid: test_identity(99).xid,
        bundle: None,
    });

    assert!(harness.next_outbound_a().is_none());
}

#[test]
fn simultaneous_xx_connect_converges() {
    let mut harness = Harness::paired_unknown(QlFsmConfig::default());

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    harness
        .b
        .fsm
        .connect(harness.time(), &harness.b.crypto)
        .unwrap();
    harness.pump();

    assert!(matches!(
        harness.a.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Connected(_))
    ));
    assert!(matches!(
        harness.b.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Connected(_))
    ));
}

#[test]
fn simultaneous_xx_and_kk_connect_prefers_xx() {
    let mut harness = Harness::paired(QlFsmConfig::default(), false, true);

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    harness
        .b
        .fsm
        .connect(harness.time(), &harness.b.crypto)
        .unwrap();
    harness.pump();

    assert_eq!(
        harness.a.fsm.peer.as_ref().unwrap().peer.bundle,
        Some(harness.b.fsm.identity.bundle())
    );
    assert!(matches!(
        harness.a.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Connected(_))
    ));
    assert!(matches!(
        harness.b.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Connected(_))
    ));
}
