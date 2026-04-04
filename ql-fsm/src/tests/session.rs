use std::time::Duration;

use ql_wire::{SessionClose, StreamId};

use super::*;
use crate::{state::LinkState, QlFsmEvent, QlSessionEvent};

fn read_stream_all(fsm: &mut QlFsm, stream_id: StreamId) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut read = 0;
        for chunk in fsm.stream_read(stream_id).unwrap() {
            out.extend_from_slice(chunk);
            read += chunk.len();
        }
        if read == 0 {
            break;
        }
        fsm.stream_read_commit(stream_id, read).unwrap();
    }
    out
}

#[test]
fn connected_fsms_deliver_stream_data() {
    let mut harness = Harness::connected(QlFsmConfig::default());

    let stream_id = harness.a.fsm.open_stream().unwrap();
    assert_eq!(harness.a.fsm.write_stream(stream_id, b"hello").unwrap(), 5);
    harness.a.fsm.finish_stream(stream_id).unwrap();

    harness.pump();

    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Opened(stream_id))
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Readable(stream_id))
    );
    assert_eq!(
        read_stream_all(&mut harness.b.fsm, stream_id),
        b"hello".to_vec()
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Finished(stream_id))
    );
}

#[test]
fn session_retransmit_uses_new_record_seq() {
    let config = QlFsmConfig::default();
    let mut harness = Harness::connected(config);

    let stream_id = harness.a.fsm.open_stream().unwrap();
    assert_eq!(harness.a.fsm.write_stream(stream_id, b"retry").unwrap(), 5);

    let first = harness.next_outbound_a().unwrap();
    let first_transport = harness.b.fsm.state.link.transport().unwrap().clone();
    let (first_header, first_record) =
        decrypt_record(&harness.b.crypto, &first, &first_transport.rx_key);

    harness.advance(config.session_record_retransmit_timeout + Duration::from_millis(1));
    harness.a.fsm.on_timer(harness.time());

    let retried = harness.next_outbound_a().unwrap();
    let (retried_header, retried_record) =
        decrypt_record(&harness.b.crypto, &retried, &first_transport.rx_key);

    assert_ne!(retried_header.seq, first_header.seq);
    assert_eq!(retried_record.frames, first_record.frames);

    harness.deliver_to_b(retried);
    harness.advance(config.session_record_ack_delay);
    harness.a.fsm.on_timer(harness.time());
    harness.b.fsm.on_timer(harness.time());
    harness.pump();

    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Opened(stream_id))
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Readable(stream_id))
    );
    assert_eq!(
        read_stream_all(&mut harness.b.fsm, stream_id),
        b"retry".to_vec()
    );

    harness.advance(config.session_record_retransmit_timeout + Duration::from_millis(1));
    harness.a.fsm.on_timer(harness.time());
    assert!(harness.next_outbound_a().is_none());
}

#[test]
fn simultaneous_opens_use_even_and_odd_stream_ids() {
    let mut harness = Harness::connected(QlFsmConfig::default());

    let stream_id_a = harness.a.fsm.open_stream().unwrap();
    let stream_id_b = harness.b.fsm.open_stream().unwrap();

    assert_ne!(stream_id_a, stream_id_b);
    assert!(
        StreamParity::for_local(harness.a.fsm.identity.xid, harness.b.fsm.identity.xid)
            .matches(stream_id_a)
    );
    assert!(
        StreamParity::for_local(harness.b.fsm.identity.xid, harness.a.fsm.identity.xid)
            .matches(stream_id_b)
    );

    assert_eq!(
        harness.a.fsm.write_stream(stream_id_a, b"from-a").unwrap(),
        6
    );
    assert_eq!(
        harness.b.fsm.write_stream(stream_id_b, b"from-b").unwrap(),
        6
    );

    harness.pump();

    assert_eq!(
        harness.a.fsm.take_next_session_event(),
        Some(QlSessionEvent::Opened(stream_id_b))
    );
    assert_eq!(
        harness.a.fsm.take_next_session_event(),
        Some(QlSessionEvent::Readable(stream_id_b))
    );
    assert_eq!(
        read_stream_all(&mut harness.a.fsm, stream_id_b),
        b"from-b".to_vec()
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Opened(stream_id_a))
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Readable(stream_id_a))
    );
    assert_eq!(
        read_stream_all(&mut harness.b.fsm, stream_id_a),
        b"from-a".to_vec()
    );
}

#[test]
fn queued_stream_work_waits_for_explicit_connect_and_then_drains() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());

    let stream_id = harness.a.fsm.open_stream().unwrap();
    assert_eq!(harness.a.fsm.write_stream(stream_id, b"queued").unwrap(), 6);
    harness.a.fsm.finish_stream(stream_id).unwrap();

    assert!(harness.next_outbound_a().is_none());

    harness
        .a
        .fsm
        .connect_ik(harness.time(), &harness.a.crypto)
        .unwrap();
    harness.pump();

    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Opened(stream_id))
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Readable(stream_id))
    );
    assert_eq!(
        read_stream_all(&mut harness.b.fsm, stream_id),
        b"queued".to_vec()
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Finished(stream_id))
    );
}

#[test]
fn queued_stream_work_is_failed_when_handshake_times_out() {
    let config = QlFsmConfig {
        handshake_timeout: Duration::from_millis(50),
        ..QlFsmConfig::default()
    };
    let mut harness = Harness::paired_known(config);

    let stream_id = harness.a.fsm.open_stream().unwrap();
    assert_eq!(harness.a.fsm.write_stream(stream_id, b"queued").unwrap(), 6);

    harness
        .a
        .fsm
        .connect_ik(harness.time(), &harness.a.crypto)
        .unwrap();
    let _first = harness.next_outbound_a().unwrap();
    harness.advance(config.handshake_timeout);
    harness.a.fsm.on_timer(harness.time());

    assert_eq!(
        harness.a.fsm.take_next_session_event(),
        Some(QlSessionEvent::SessionClosed(SessionClose {
            code: ql_wire::SessionCloseCode::TIMEOUT
        }))
    );
    assert!(harness.next_outbound_a().is_none());
}

#[test]
fn returned_session_write_is_reissued_with_new_record_seq() {
    let mut harness = Harness::connected(QlFsmConfig::default());

    let stream_id = harness.a.fsm.open_stream().unwrap();
    assert_eq!(harness.a.fsm.write_stream(stream_id, b"retry").unwrap(), 5);

    let write = harness.next_write_a().unwrap();
    let id = write.session_write_id.expect("expected session write");
    let record = write.record;
    let session_key = harness.b.fsm.state.link.transport().unwrap().rx_key.clone();
    let (first_header, first) = decrypt_record(&harness.b.crypto, &record, &session_key);

    harness.return_write_a(id);

    let write = harness.next_write_a().unwrap();
    let reissued_id = write.session_write_id.expect("expected reissued write");
    let record = write.record;
    let (reissued_header, reissued) = decrypt_record(&harness.b.crypto, &record, &session_key);

    assert_ne!(reissued_id, id);
    assert_ne!(reissued_header.seq, first_header.seq);
    assert_eq!(reissued.frames, first.frames);

    harness.confirm_write_a(reissued_id);
    harness.deliver_to_b(record);
    harness.pump();

    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Opened(stream_id))
    );
    assert_eq!(
        harness.b.fsm.take_next_session_event(),
        Some(QlSessionEvent::Readable(stream_id))
    );
    assert_eq!(
        read_stream_all(&mut harness.b.fsm, stream_id),
        b"retry".to_vec()
    );
}

#[test]
fn unconfirmed_session_write_does_not_start_retransmit_timer() {
    let config = QlFsmConfig::default();
    let mut harness = Harness::connected(config);

    let stream_id = harness.a.fsm.open_stream().unwrap();
    assert_eq!(harness.a.fsm.write_stream(stream_id, b"retry").unwrap(), 5);

    let write = harness.next_write_a().unwrap();
    let id = write.session_write_id.expect("expected session write");
    let record = write.record;
    let session_key = harness.b.fsm.state.link.transport().unwrap().rx_key.clone();
    let (first_header, first) = decrypt_record(&harness.b.crypto, &record, &session_key);

    harness.advance(config.session_record_retransmit_timeout + Duration::from_millis(1));
    harness.a.fsm.on_timer(harness.time());
    assert!(harness.next_write_a().is_none());

    harness.confirm_write_a(id);
    harness.advance(config.session_record_retransmit_timeout + Duration::from_millis(1));
    harness.a.fsm.on_timer(harness.time());

    let write = harness.next_write_a().unwrap();
    let record = write.record;
    let (retried_header, retried) = decrypt_record(&harness.b.crypto, &record, &session_key);

    assert_ne!(retried_header.seq, first_header.seq);
    assert_eq!(retried.frames, first.frames);
}

#[test]
fn ack_frame_releases_stream_capacity_and_emits_writable() {
    let config = QlFsmConfig {
        session_stream_send_buffer_size: 4,
        ..QlFsmConfig::default()
    };
    let mut harness = Harness::connected(config);

    let stream_id = harness.a.fsm.open_stream().unwrap();
    assert_eq!(harness.a.fsm.write_stream(stream_id, b"abcd").unwrap(), 4);
    assert_eq!(harness.a.fsm.write_stream(stream_id, b"z").unwrap(), 0);

    let record = harness.next_outbound_a().unwrap();
    harness.deliver_to_b(record);
    harness.advance(config.session_record_ack_delay);
    harness.a.fsm.on_timer(harness.time());
    harness.b.fsm.on_timer(harness.time());
    harness.pump();

    assert_eq!(
        harness.a.fsm.take_next_session_event(),
        Some(QlSessionEvent::Writable(stream_id))
    );
}

#[test]
fn kill_session_disconnects_locally() {
    let mut harness = Harness::connected(QlFsmConfig::default());

    harness
        .a
        .fsm
        .kill_session(ql_wire::SessionCloseCode::CANCELLED);

    assert!(matches!(harness.a.fsm.state.link, LinkState::Idle));
    assert_eq!(
        harness.a.fsm.take_next_session_event(),
        Some(QlSessionEvent::SessionClosed(SessionClose {
            code: ql_wire::SessionCloseCode::CANCELLED
        }))
    );
    assert!(matches!(
        harness.a.fsm.take_next_event(),
        Some(QlFsmEvent::PeerStatusChanged { .. })
    ));
}

#[test]
fn session_records_contain_ack_frames_after_delivery() {
    let config = QlFsmConfig::default();
    let mut harness = Harness::connected(config);

    let stream_id = harness.a.fsm.open_stream().unwrap();
    assert_eq!(harness.a.fsm.write_stream(stream_id, b"x").unwrap(), 1);

    let data = harness.next_outbound_a().unwrap();
    harness.deliver_to_b(data);
    harness.advance(config.session_record_ack_delay);
    harness.b.fsm.on_timer(harness.time());

    let ack = harness.next_outbound_b().unwrap();
    let session_key = harness.a.fsm.state.link.transport().unwrap().rx_key.clone();
    let (_ack_header, ack_record) = decrypt_record(&harness.a.crypto, &ack, &session_key);
    assert!(matches!(
        ack_record.frames.as_slice(),
        [ql_wire::SessionFrame::Ack(_)]
    ));
}

#[test]
fn queued_stream_work_uses_negotiated_initial_peer_credit_after_connect() {
    let mut harness = Harness::paired_known_with_configs(
        QlFsmConfig {
            session_stream_receive_buffer_size: 8,
            ..QlFsmConfig::default()
        },
        QlFsmConfig {
            session_stream_receive_buffer_size: 3,
            ..QlFsmConfig::default()
        },
    );

    let stream_id = harness.a.fsm.open_stream().unwrap();
    assert_eq!(harness.a.fsm.write_stream(stream_id, b"hello").unwrap(), 5);

    harness
        .a
        .fsm
        .connect_ik(harness.time(), &harness.a.crypto)
        .unwrap();
    let ik1 = harness.next_outbound_a().unwrap();
    harness.deliver_to_b(ik1);
    let ik2 = harness.next_outbound_b().unwrap();
    harness.deliver_to_a(ik2);

    let data = harness.next_outbound_a().unwrap();
    let session_key = harness.b.fsm.state.link.transport().unwrap().rx_key.clone();
    let (_header, record) = decrypt_record(&harness.b.crypto, &data, &session_key);

    assert!(matches!(
        record.frames.as_slice(),
        [ql_wire::SessionFrame::StreamData(frame)] if frame.stream_id == stream_id && frame.bytes.as_slice() == b"hel"
    ));
}
