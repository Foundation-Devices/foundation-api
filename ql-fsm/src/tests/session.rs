use std::time::Duration;

use bytes::Bytes;
use ql_wire::{RouteId, SessionClose, StreamId, VarInt};

use super::*;
use crate::{
    state::LinkState, CommitReadError, NoSessionError, PeerStatus, QlFsmEvent, StreamError,
};

fn stream_id(value: u32) -> StreamId {
    StreamId(VarInt::from_u32(value))
}

fn route_id(value: u32) -> RouteId {
    RouteId(VarInt::from_u32(value))
}

fn opened(stream_id: StreamId) -> QlFsmEvent {
    QlFsmEvent::Opened {
        stream_id,
        route_id: route_id(1),
    }
}

fn open_stream_id(fsm: &mut QlFsm) -> StreamId {
    fsm.open_stream(route_id(1)).unwrap().stream_id()
}

fn write_stream_bytes(
    fsm: &mut QlFsm,
    stream_id: StreamId,
    bytes: &[u8],
) -> Result<usize, StreamError> {
    let mut bytes = Bytes::copy_from_slice(bytes);
    let mut stream = fsm.stream(stream_id)?;
    let Some(mut writer) = stream.writer() else {
        return Err(StreamError::NotWritable);
    };
    Ok(writer.write(&mut bytes))
}

fn read_stream_all(fsm: &mut QlFsm, stream_id: StreamId) -> Vec<u8> {
    let mut out = Vec::new();
    let Ok(mut stream) = fsm.stream(stream_id) else {
        return out;
    };
    loop {
        let mut read = 0;
        for chunk in stream.read() {
            out.extend_from_slice(&chunk);
            read += chunk.len();
        }
        if read == 0 {
            break;
        }
        stream.commit_read(read).unwrap();
    }
    out
}

#[test]
fn connected_fsms_deliver_stream_data() {
    let mut harness = Harness::connected(QlFsmConfig::default());

    let stream_id = open_stream_id(&mut harness.a.fsm);
    assert_eq!(
        write_stream_bytes(&mut harness.a.fsm, stream_id, b"hello").unwrap(),
        5
    );
    harness
        .a
        .fsm
        .stream(stream_id)
        .unwrap()
        .writer()
        .unwrap()
        .finish();

    harness.pump();

    assert_eq!(harness.take_event_b(), Some(opened(stream_id)));
    assert_eq!(
        harness.take_event_b(),
        Some(QlFsmEvent::Readable(stream_id))
    );
    assert_eq!(
        read_stream_all(&mut harness.b.fsm, stream_id),
        b"hello".to_vec()
    );
    assert_eq!(
        harness.take_event_b(),
        Some(QlFsmEvent::Finished(stream_id))
    );
}

#[test]
fn session_retransmit_uses_new_record_seq() {
    let config = QlFsmConfig::default();
    let mut harness = Harness::connected(config);

    let stream_id = open_stream_id(&mut harness.a.fsm);
    assert_eq!(
        write_stream_bytes(&mut harness.a.fsm, stream_id, b"retry").unwrap(),
        5
    );

    let first = harness.next_outbound_a().unwrap();
    let first_transport = harness.b.fsm.state.link.transport().unwrap().clone();
    let (first_header, first_record) =
        decrypt_record(&harness.b.crypto, &first, &first_transport.rx_key);

    harness.advance(config.session_record_retransmit_timeout + Duration::from_millis(1));
    harness.on_timer_a();

    let retried = harness.next_outbound_a().unwrap();
    let (retried_header, retried_record) =
        decrypt_record(&harness.b.crypto, &retried, &first_transport.rx_key);

    assert_ne!(retried_header.seq, first_header.seq);
    assert_eq!(retried_record, first_record);

    harness.deliver_to_b(retried);
    harness.advance(config.session_record_ack_delay);
    harness.on_timer_a();
    harness.on_timer_b();
    harness.pump();

    assert_eq!(harness.take_event_b(), Some(opened(stream_id)));
    assert_eq!(
        harness.take_event_b(),
        Some(QlFsmEvent::Readable(stream_id))
    );
    assert_eq!(
        read_stream_all(&mut harness.b.fsm, stream_id),
        b"retry".to_vec()
    );

    harness.advance(config.session_record_retransmit_timeout + Duration::from_millis(1));
    harness.on_timer_a();
    assert!(harness.next_outbound_a().is_none());
}

#[test]
fn simultaneous_opens_use_even_and_odd_stream_ids() {
    let mut harness = Harness::connected(QlFsmConfig::default());

    let stream_id_a = open_stream_id(&mut harness.a.fsm);
    let stream_id_b = open_stream_id(&mut harness.b.fsm);

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
        write_stream_bytes(&mut harness.a.fsm, stream_id_a, b"from-a").unwrap(),
        6
    );
    assert_eq!(
        write_stream_bytes(&mut harness.b.fsm, stream_id_b, b"from-b").unwrap(),
        6
    );

    harness.pump();

    assert_eq!(
        harness.take_event_a(),
        Some(opened(stream_id_b))
    );
    assert_eq!(
        harness.take_event_a(),
        Some(QlFsmEvent::Readable(stream_id_b))
    );
    assert_eq!(
        read_stream_all(&mut harness.a.fsm, stream_id_b),
        b"from-b".to_vec()
    );
    assert_eq!(
        harness.take_event_b(),
        Some(opened(stream_id_a))
    );
    assert_eq!(
        harness.take_event_b(),
        Some(QlFsmEvent::Readable(stream_id_a))
    );
    assert_eq!(
        read_stream_all(&mut harness.b.fsm, stream_id_a),
        b"from-a".to_vec()
    );
}

#[test]
fn disconnected_stream_operations_fail_with_no_session() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());
    let missing = stream_id(0);

    assert!(matches!(harness.a.fsm.open_stream(route_id(1)), Err(NoSessionError)));
    assert_eq!(
        write_stream_bytes(&mut harness.a.fsm, missing, b"queued"),
        Err(StreamError::NoSession)
    );
    assert_eq!(
        harness
            .a
            .fsm
            .stream(missing)
            .map(|mut stream| stream.writer().unwrap().finish()),
        Err(StreamError::NoSession)
    );
    assert_eq!(
        harness
            .a
            .fsm
            .stream(missing)
            .map(|mut stream| stream.close(ql_wire::CloseTarget::Both, ql_wire::StreamCloseCode(0))),
        Err(StreamError::NoSession)
    );
    assert_eq!(harness.a.fsm.queue_ping(), Err(NoSessionError));
    assert!(matches!(
        harness.a.fsm.stream(missing),
        Err(StreamError::NoSession)
    ));
}

#[test]
fn disconnected_stream_read_accessors_return_none() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());
    let missing = stream_id(0);

    assert!(matches!(
        harness.a.fsm.stream(missing),
        Err(StreamError::NoSession)
    ));
}

#[test]
fn commit_read_rejects_lengths_past_readable_prefix() {
    let mut harness = Harness::connected(QlFsmConfig::default());

    let stream_id = open_stream_id(&mut harness.a.fsm);
    assert_eq!(
        write_stream_bytes(&mut harness.a.fsm, stream_id, b"hi").unwrap(),
        2
    );
    harness.pump();

    let mut stream = harness.b.fsm.stream(stream_id).unwrap();
    assert_eq!(stream.commit_read(3), Err(CommitReadError));
}

#[test]
fn returned_session_write_is_reissued_with_new_record_seq() {
    let mut harness = Harness::connected(QlFsmConfig::default());

    let stream_id = open_stream_id(&mut harness.a.fsm);
    assert_eq!(
        write_stream_bytes(&mut harness.a.fsm, stream_id, b"retry").unwrap(),
        5
    );

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
    assert_eq!(reissued, first);

    harness.confirm_write_a(reissued_id);
    harness.deliver_to_b(record);
    harness.pump();

    assert_eq!(harness.take_event_b(), Some(opened(stream_id)));
    assert_eq!(
        harness.take_event_b(),
        Some(QlFsmEvent::Readable(stream_id))
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

    let stream_id = open_stream_id(&mut harness.a.fsm);
    assert_eq!(
        write_stream_bytes(&mut harness.a.fsm, stream_id, b"retry").unwrap(),
        5
    );

    let write = harness.next_write_a().unwrap();
    let id = write.session_write_id.expect("expected session write");
    let record = write.record;
    let session_key = harness.b.fsm.state.link.transport().unwrap().rx_key.clone();
    let (first_header, first) = decrypt_record(&harness.b.crypto, &record, &session_key);

    harness.advance(config.session_record_retransmit_timeout + Duration::from_millis(1));
    harness.on_timer_a();
    assert!(harness.next_write_a().is_none());

    harness.confirm_write_a(id);
    harness.advance(config.session_record_retransmit_timeout + Duration::from_millis(1));
    harness.on_timer_a();

    let write = harness.next_write_a().unwrap();
    let record = write.record;
    let (retried_header, retried) = decrypt_record(&harness.b.crypto, &record, &session_key);

    assert_ne!(retried_header.seq, first_header.seq);
    assert_eq!(retried, first);
}

#[test]
fn ack_frame_releases_stream_capacity_and_emits_writable() {
    let config = QlFsmConfig {
        session_stream_send_buffer_size: 4,
        ..QlFsmConfig::default()
    };
    let mut harness = Harness::connected(config);

    let stream_id = open_stream_id(&mut harness.a.fsm);
    assert_eq!(
        write_stream_bytes(&mut harness.a.fsm, stream_id, b"abcd").unwrap(),
        4
    );
    assert_eq!(
        write_stream_bytes(&mut harness.a.fsm, stream_id, b"z").unwrap(),
        0
    );

    let record = harness.next_outbound_a().unwrap();
    harness.deliver_to_b(record);
    harness.advance(config.session_record_ack_delay);
    harness.on_timer_a();
    harness.on_timer_b();
    harness.pump();

    assert_eq!(
        harness.take_event_a(),
        Some(QlFsmEvent::Writable(stream_id))
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
    assert!(harness.drain_events_a().is_empty());
}

#[test]
fn session_records_contain_ack_frames_after_delivery() {
    let config = QlFsmConfig::default();
    let mut harness = Harness::connected(config);

    let stream_id = open_stream_id(&mut harness.a.fsm);
    assert_eq!(
        write_stream_bytes(&mut harness.a.fsm, stream_id, b"x").unwrap(),
        1
    );

    let data = harness.next_outbound_a().unwrap();
    harness.deliver_to_b(data);
    harness.advance(config.session_record_ack_delay);
    harness.on_timer_b();

    let ack = harness.next_outbound_b().unwrap();
    let session_key = harness.a.fsm.state.link.transport().unwrap().rx_key.clone();
    let (_ack_header, ack_record) = decrypt_record(&harness.a.crypto, &ack, &session_key);
    assert!(matches!(
        ack_record.as_slice(),
        [ql_wire::SessionFrame::Ack(_)]
    ));
}

#[test]
fn first_stream_data_uses_negotiated_initial_peer_credit() {
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

    harness.connect_ik_a().unwrap();
    let ik1 = harness.next_outbound_a().unwrap();
    harness.deliver_to_b(ik1);
    let ik2 = harness.next_outbound_b().unwrap();
    harness.deliver_to_a(ik2);

    let stream_id = open_stream_id(&mut harness.a.fsm);
    assert_eq!(
        write_stream_bytes(&mut harness.a.fsm, stream_id, b"hello").unwrap(),
        5
    );

    let data = harness.next_outbound_a().unwrap();
    let session_key = harness.b.fsm.state.link.transport().unwrap().rx_key.clone();
    let (_header, record) = decrypt_record(&harness.b.crypto, &data, &session_key);

    assert!(matches!(
        record.as_slice(),
        [ql_wire::SessionFrame::StreamData(frame)] if frame.stream_id == stream_id && frame.bytes.as_slice() == b"hel"
    ));
}

#[test]
fn session_timeout_emits_close_before_disconnect() {
    let config = QlFsmConfig {
        session_peer_timeout: Duration::from_millis(30),
        ..QlFsmConfig::default()
    };
    let mut harness = Harness::connected(config);

    harness.advance(config.session_peer_timeout);
    harness.on_timer_a();

    assert_eq!(
        harness.drain_events_a(),
        vec![
            QlFsmEvent::SessionClosed(SessionClose {
                code: ql_wire::SessionCloseCode::TIMEOUT,
            }),
            QlFsmEvent::PeerStatusChanged(PeerStatus::Disconnected),
        ]
    );
}
