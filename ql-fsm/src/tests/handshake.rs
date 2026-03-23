use std::time::Duration;

use ql_wire::{QlPayload, XID};

use super::*;
use crate::state::{ConnectionState, HandshakeInitiator, HandshakeResponder};

#[test]
fn handshake_deadline_is_derived_from_peer_state() {
    let config = QlFsmConfig {
        handshake_timeout: Duration::from_secs(5),
        handshake_retry_interval: Duration::from_secs(10),
        max_handshake_retries: 0,
        session_keepalive_interval: Duration::from_millis(1),
        session_peer_timeout: Duration::from_millis(2),
        ..QlFsmConfig::default()
    };
    let mut harness = Harness::paired(config);

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    assert_eq!(
        harness.a.fsm.next_deadline(),
        Some(harness.now + config.handshake_timeout)
    );

    let _hello = harness.next_outbound_a().unwrap();
    harness.advance(Duration::from_secs(4));
    harness.a.fsm.on_timer(harness.time());
    assert!(matches!(
        harness.a.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Initiator { .. })
    ));

    harness.advance(Duration::from_secs(1));
    harness.a.fsm.on_timer(harness.time());
    assert!(matches!(
        harness.a.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Disconnected)
    ));
}

#[test]
fn initiator_retries_hello_after_retry_interval() {
    let config = QlFsmConfig {
        handshake_retry_interval: Duration::from_millis(250),
        max_handshake_retries: 2,
        ..QlFsmConfig::default()
    };
    let mut harness = Harness::paired(config);

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    let hello = harness.next_outbound_a().unwrap();

    harness.advance(config.handshake_retry_interval);
    harness.a.fsm.on_timer(harness.time());

    assert_eq!(harness.next_outbound_a(), Some(hello));
    assert!(matches!(
        harness.a.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Initiator {
            stage: HandshakeInitiator::WaitingHelloReply { retry_count: 1, .. },
            ..
        })
    ));
}

#[test]
fn responder_retries_hello_reply_after_retry_interval() {
    let config = QlFsmConfig {
        handshake_retry_interval: Duration::from_millis(250),
        max_handshake_retries: 2,
        ..QlFsmConfig::default()
    };
    let mut harness = Harness::paired(config);

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    let hello = harness.next_outbound_a().unwrap();
    harness.deliver_to_b(hello);
    let reply = harness.next_outbound_b().unwrap();

    harness.advance(config.handshake_retry_interval);
    harness.b.fsm.on_timer(harness.time());

    assert_eq!(harness.next_outbound_b(), Some(reply));
    assert!(matches!(
        harness.b.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Responder {
            stage: HandshakeResponder::WaitingConfirm { retry_count: 1, .. },
            ..
        })
    ));
}

#[test]
fn initiator_retries_confirm_after_retry_interval() {
    let config = QlFsmConfig {
        handshake_retry_interval: Duration::from_millis(250),
        max_handshake_retries: 2,
        ..QlFsmConfig::default()
    };
    let mut harness = Harness::paired(config);

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    let hello = harness.next_outbound_a().unwrap();
    harness.deliver_to_b(hello);
    let reply = harness.next_outbound_b().unwrap();
    harness.deliver_to_a(reply);
    let confirm = harness.next_outbound_a().unwrap();

    harness.advance(config.handshake_retry_interval);
    harness.a.fsm.on_timer(harness.time());

    assert_eq!(harness.next_outbound_a(), Some(confirm));
    assert!(matches!(
        harness.a.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Initiator {
            stage: HandshakeInitiator::WaitingReady { retry_count: 1, .. },
            ..
        })
    ));
}

#[test]
fn duplicate_hello_resends_hello_reply() {
    let mut harness = Harness::paired(QlFsmConfig::default());

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    let hello = harness.next_outbound_a().unwrap();

    harness.deliver_to_b(hello.clone());
    let reply = harness.next_outbound_b().unwrap();

    harness.deliver_to_b(hello);
    assert_eq!(harness.next_outbound_b(), Some(reply));
}

#[test]
fn duplicate_hello_reply_resends_confirm() {
    let mut harness = Harness::paired(QlFsmConfig::default());

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    let hello = harness.next_outbound_a().unwrap();
    harness.deliver_to_b(hello);
    let reply = harness.next_outbound_b().unwrap();

    harness.deliver_to_a(reply.clone());
    let confirm = harness.next_outbound_a().unwrap();

    harness.deliver_to_a(reply);
    assert_eq!(harness.next_outbound_a(), Some(confirm));
}

#[test]
fn responder_resends_ready_for_duplicate_confirm_after_connecting() {
    let mut harness = Harness::paired(QlFsmConfig::default());

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    let hello = harness.next_outbound_a().unwrap();
    harness.deliver_to_b(hello);
    let reply = harness.next_outbound_b().unwrap();
    harness.deliver_to_a(reply);
    let confirm = harness.next_outbound_a().unwrap();

    harness.deliver_to_b(confirm.clone());
    let ready = harness.next_outbound_b().unwrap();

    assert!(matches!(
        harness.b.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Connected {
            recent_ready: Some(_),
            ..
        })
    ));

    harness.deliver_to_b(confirm);
    assert_eq!(harness.next_outbound_b(), Some(ready));
}

#[test]
fn initiator_waits_for_ready_before_connecting() {
    let mut harness = Harness::paired(QlFsmConfig::default());

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    let hello = harness.next_outbound_a().unwrap();
    harness.deliver_to_b(hello);
    let reply = harness.next_outbound_b().unwrap();
    harness.deliver_to_a(reply);

    assert!(matches!(
        harness.a.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Initiator {
            stage: HandshakeInitiator::WaitingReady { .. },
            ..
        })
    ));
    let stream_id = harness.a.fsm.open_stream().unwrap();
    harness
        .a
        .fsm
        .write_stream(stream_id, b"queued".to_vec())
        .unwrap();

    let confirm = harness.next_outbound_a().unwrap();
    assert!(matches!(confirm.payload, QlPayload::Confirm(_)));
    harness.deliver_to_b(confirm);
    let ready = harness.next_outbound_b().unwrap();

    assert!(matches!(
        harness.a.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Initiator {
            stage: HandshakeInitiator::WaitingReady { .. },
            ..
        })
    ));

    harness.deliver_to_a(ready);
    assert!(matches!(
        harness.a.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Connected { .. })
    ));
    let record = harness.next_outbound_a().unwrap();
    assert!(matches!(record.payload, QlPayload::Session(_)));
}

#[test]
fn handshake_retry_limit_disconnects_initiator() {
    let config = QlFsmConfig {
        handshake_retry_interval: Duration::from_millis(250),
        max_handshake_retries: 1,
        ..QlFsmConfig::default()
    };
    let mut harness = Harness::paired(config);

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    let hello = harness.next_outbound_a().unwrap();

    harness.advance(config.handshake_retry_interval);
    harness.a.fsm.on_timer(harness.time());
    assert_eq!(harness.next_outbound_a(), Some(hello));

    harness.advance(config.handshake_retry_interval);
    harness.a.fsm.on_timer(harness.time());
    assert!(matches!(
        harness.a.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Disconnected)
    ));
}

#[test]
fn simultaneous_connect_converges_to_connected_peers() {
    let mut harness = Harness::paired(QlFsmConfig::default());

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

    let hello_a = harness.next_outbound_a().unwrap();
    let hello_b = harness.next_outbound_b().unwrap();

    harness.deliver_to_a(hello_b);
    harness.deliver_to_b(hello_a);
    harness.pump();

    assert!(matches!(
        harness.a.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Connected { .. })
    ));
    assert!(matches!(
        harness.b.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Connected { .. })
    ));
}

#[test]
fn receive_surfaces_invalid_xid_for_wrong_recipient() {
    let mut harness = Harness::paired(QlFsmConfig::default());

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    let mut hello = harness.next_outbound_a().unwrap();
    hello.header.recipient = XID([0xAA; XID::SIZE]);

    assert_eq!(
        harness
            .b
            .fsm
            .receive(harness.time(), hello.encode(), &harness.b.crypto),
        Err(crate::QlFsmError::InvalidXid)
    );
}

#[test]
fn receive_surfaces_invalid_signature_for_tampered_hello() {
    let mut harness = Harness::paired(QlFsmConfig::default());

    harness
        .a
        .fsm
        .connect(harness.time(), &harness.a.crypto)
        .unwrap();
    let hello = harness.next_outbound_a().unwrap();
    let mut bytes = hello.encode();
    *bytes.last_mut().unwrap() ^= 0x01;

    assert_eq!(
        harness
            .b
            .fsm
            .receive(harness.time(), bytes, &harness.b.crypto),
        Err(crate::QlFsmError::InvalidSignature)
    );
}
