use std::time::Duration;

use ql_wire::SessionCloseBody;

use super::*;
use crate::{session::StreamNamespace, QlFsmEvent, QlSessionEvent};

#[test]
fn connected_fsms_deliver_stream_data() {
    let mut harness = Harness::connected(QlFsmConfig::default());

    let stream_id = harness.a.fsm.open_stream().unwrap();
    harness
        .a
        .fsm
        .write_stream(stream_id, b"hello".to_vec())
        .unwrap();
    harness.a.fsm.finish_stream(stream_id).unwrap();

    harness.pump();

    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Opened(stream_id))
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Data {
            stream_id,
            bytes: b"hello".to_vec(),
        })
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Finished(stream_id))
    );
}

#[test]
fn lost_encrypted_record_is_retried_and_acked() {
    let config = QlFsmConfig::default();
    let mut harness = Harness::connected(config);

    let stream_id = harness.a.fsm.open_stream().unwrap();
    harness
        .a
        .fsm
        .write_stream(stream_id, b"retry".to_vec())
        .unwrap();

    let first = harness.next_outbound_a().unwrap();
    let session_key = harness
        .b
        .fsm
        .peer
        .as_ref()
        .unwrap()
        .session
        .session_key()
        .unwrap()
        .clone();
    let first_body = decrypt_envelope(&first, &session_key);

    harness.advance(config.session_retransmit_timeout + Duration::from_millis(1));

    let retried = harness.next_outbound_a().unwrap();
    let retried_body = decrypt_envelope(&retried, &session_key);

    assert_ne!(first_body.seq, retried_body.seq);
    assert_eq!(first_body.body, retried_body.body);

    harness.deliver_to_b(retried);
    harness.pump();

    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Opened(stream_id))
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Data {
            stream_id,
            bytes: b"retry".to_vec(),
        })
    );

    harness.advance(config.session_retransmit_timeout + Duration::from_millis(1));
    assert!(harness.next_outbound_a().is_none());
}

#[test]
fn remote_unpair_clears_peer() {
    let mut harness = Harness::connected(QlFsmConfig::default());

    harness.a.fsm.queue_unpair().unwrap();
    harness.pump();

    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Unpaired)
    );
    assert!(harness.b.fsm.peer.is_none());
    assert!(matches!(
        harness.b.fsm.take_next_event(),
        Some(QlFsmEvent::ClearPeer)
    ));
    assert!(harness.a.fsm.peer.is_some());
}

#[test]
fn simultaneous_opens_use_disjoint_stream_id_namespaces() {
    let mut harness = Harness::connected(QlFsmConfig::default());

    let stream_id_a = harness.a.fsm.open_stream().unwrap();
    let stream_id_b = harness.b.fsm.open_stream().unwrap();

    assert_ne!(stream_id_a, stream_id_b);
    assert!(
        StreamNamespace::for_local(harness.a.fsm.identity.xid, harness.b.fsm.identity.xid)
            .matches(stream_id_a)
    );
    assert!(
        StreamNamespace::for_local(harness.b.fsm.identity.xid, harness.a.fsm.identity.xid)
            .matches(stream_id_b)
    );

    harness
        .a
        .fsm
        .write_stream(stream_id_a, b"from-a".to_vec())
        .unwrap();
    harness
        .b
        .fsm
        .write_stream(stream_id_b, b"from-b".to_vec())
        .unwrap();

    harness.pump();

    assert_eq!(
        harness.a.fsm.take_next_session_event(),
        Some(QlSessionEvent::Opened(stream_id_b))
    );
    assert_eq!(
        harness.a.fsm.take_next_session_event(),
        Some(QlSessionEvent::Data {
            stream_id: stream_id_b,
            bytes: b"from-b".to_vec(),
        })
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Opened(stream_id_a))
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Data {
            stream_id: stream_id_a,
            bytes: b"from-a".to_vec(),
        })
    );
}

#[test]
fn queued_stream_work_auto_connects_and_drains_after_handshake() {
    let mut harness = Harness::paired(QlFsmConfig::default());

    let stream_id = harness.a.fsm.open_stream().unwrap();
    harness
        .a
        .fsm
        .write_stream(stream_id, b"queued".to_vec())
        .unwrap();
    harness.a.fsm.finish_stream(stream_id).unwrap();

    harness.pump();

    assert!(matches!(
        harness.a.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(crate::state::ConnectionState::Connected { .. })
    ));
    assert!(matches!(
        harness.b.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(crate::state::ConnectionState::Connected { .. })
    ));
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Opened(stream_id))
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Data {
            stream_id,
            bytes: b"queued".to_vec(),
        })
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Finished(stream_id))
    );
}

#[test]
fn queued_stream_work_is_failed_when_handshake_times_out() {
    let config = QlFsmConfig {
        handshake_retry_interval: Duration::from_millis(50),
        max_handshake_retries: 0,
        ..QlFsmConfig::default()
    };
    let mut harness = Harness::paired(config);

    let stream_id = harness.a.fsm.open_stream().unwrap();
    harness
        .a
        .fsm
        .write_stream(stream_id, b"queued".to_vec())
        .unwrap();

    let _hello = harness.next_outbound_a().unwrap();

    harness.advance(config.handshake_retry_interval);
    harness.a.fsm.on_timer(harness.time());

    assert!(matches!(
        harness.a.fsm.peer.as_ref().map(|entry| &entry.session),
        Some(crate::state::ConnectionState::Disconnected)
    ));
    assert_eq!(
        harness.a.fsm.take_next_session_event(),
        Some(QlSessionEvent::SessionClosed(SessionCloseBody {
            code: ql_wire::CloseCode::TIMEOUT
        }))
    );
    assert!(harness.next_outbound_a().is_none());
}
