use std::time::Duration;

use bytes::Bytes;
use ql_common::StreamId;
use ql_wire::SessionClose;

use super::*;
use crate::{
    state::LinkState, CommitReadError, Event, NoSessionError, PeerStatus, ReaderState, StreamError,
    WriterState,
};

fn open_stream_id(fsm: &mut QlFsm<()>) -> StreamId {
    fsm.open_stream(Box::from([1])).unwrap().io().stream_id()
}

fn write_stream_bytes(
    fsm: &mut QlFsm<()>,
    stream_id: StreamId,
    bytes: &[u8],
) -> Result<usize, StreamError> {
    let mut bytes = Bytes::copy_from_slice(bytes);
    let mut stream = fsm.stream(stream_id)?;
    let mut io = stream.io();
    let mut writer = io.writer().active().expect("stream is not writable");
    Ok(writer.write(&mut bytes))
}

fn read_stream_all(fsm: &mut QlFsm<()>, stream_id: StreamId) -> Vec<u8> {
    let mut out = Vec::new();
    let Ok(mut stream) = fsm.stream(stream_id) else {
        return out;
    };
    loop {
        let mut io = stream.io();
        let Some(mut reader) = io.reader().active() else {
            break;
        };
        let mut read = 0;
        for chunk in reader.read() {
            out.extend_from_slice(&chunk);
            read += chunk.len();
        }
        reader.commit_read(read).unwrap();
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
        .io()
        .writer()
        .active()
        .unwrap()
        .finish();

    harness.pump();

    assert_eq!(harness.take_event(Side::B), Some(Event::Opened(stream_id)));
    assert_eq!(
        read_stream_all(&mut harness.b.fsm, stream_id),
        b"hello".to_vec()
    );
    assert!(matches!(
        harness.b.fsm.stream(stream_id).unwrap().io().reader(),
        ReaderState::Finished
    ));
    assert_eq!(harness.take_event(Side::B), None);
    harness.advance(QlFsmConfig::default().session.ack_delay);
    harness.on_timer(Side::B);
    harness.pump();
    assert!(matches!(
        harness.a.fsm.stream(stream_id).unwrap().io().writer(),
        WriterState::Finished
    ));
    assert_eq!(harness.take_event(Side::A), None);
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

    let first = harness.next_decoded_outbound(Side::A).unwrap();

    harness.advance(config.session.retransmit_timeout + Duration::from_millis(1));
    harness.on_timer(Side::A);

    let retried = harness.next_decoded_outbound(Side::A).unwrap();

    assert_ne!(retried.header.seq, first.header.seq);
    assert_eq!(retried.frames, first.frames);

    harness.deliver(Side::B, retried.record);
    harness.advance(config.session.ack_delay);
    harness.on_timer(Side::A);
    harness.on_timer(Side::B);
    harness.pump();

    assert_eq!(harness.take_event(Side::B), Some(Event::Opened(stream_id)));
    assert_eq!(
        read_stream_all(&mut harness.b.fsm, stream_id),
        b"retry".to_vec()
    );

    harness.advance(config.session.retransmit_timeout + Duration::from_millis(1));
    harness.on_timer(Side::A);
    assert!(harness.next_outbound(Side::A).is_none());
}

#[test]
fn simultaneous_opens_use_even_and_odd_stream_ids() {
    let mut harness = Harness::connected(QlFsmConfig::default());

    let stream_id_a = open_stream_id(&mut harness.a.fsm);
    let stream_id_b = open_stream_id(&mut harness.b.fsm);

    assert_ne!(stream_id_a, stream_id_b);
    assert!(
        StreamParity::for_local(harness.a.fsm.identity.qid, harness.b.fsm.identity.qid)
            .matches(stream_id_a)
    );
    assert!(
        StreamParity::for_local(harness.b.fsm.identity.qid, harness.a.fsm.identity.qid)
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
        harness.take_event(Side::A),
        Some(Event::Opened(stream_id_b))
    );
    assert_eq!(
        read_stream_all(&mut harness.a.fsm, stream_id_b),
        b"from-b".to_vec()
    );
    assert_eq!(
        harness.take_event(Side::B),
        Some(Event::Opened(stream_id_a))
    );
    assert_eq!(
        read_stream_all(&mut harness.b.fsm, stream_id_a),
        b"from-a".to_vec()
    );
}

#[test]
fn disconnected_stream_operations_fail_with_no_session() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());
    let missing = StreamId(0);

    assert!(matches!(
        harness.a.fsm.open_stream(Box::from([1])),
        Err(NoSessionError)
    ));
    assert_eq!(
        write_stream_bytes(&mut harness.a.fsm, missing, b"queued"),
        Err(StreamError::NoSession)
    );
    assert_eq!(
        harness.a.fsm.stream(missing).map(|mut stream| stream
            .io()
            .writer()
            .active()
            .unwrap()
            .finish()),
        Err(StreamError::NoSession)
    );
    assert_eq!(
        harness.a.fsm.stream(missing).map(|mut stream| {
            stream.reset(
                crate::StreamResetTarget::Both,
                ql_common::ResetCode::CANCELLED,
            );
        }),
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
    let missing = StreamId(0);

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
    assert_eq!(
        stream.io().reader().active().unwrap().commit_read(3),
        Err(CommitReadError)
    );
}

#[test]
fn returned_session_write_is_reissued_with_new_record_seq() {
    let mut harness = Harness::connected(QlFsmConfig::default());

    let stream_id = open_stream_id(&mut harness.a.fsm);
    assert_eq!(
        write_stream_bytes(&mut harness.a.fsm, stream_id, b"retry").unwrap(),
        5
    );

    let first = harness.next_decoded_write(Side::A).unwrap();
    let id = first.write_id.expect("expected session write");

    harness.reject_write(Side::A, id);

    let reissued = harness.next_decoded_write(Side::A).unwrap();
    let reissued_id = reissued.write_id.expect("expected reissued write");

    assert_ne!(reissued_id, id);
    assert_ne!(reissued.header.seq, first.header.seq);
    assert_eq!(reissued.frames, first.frames);

    harness.confirm_write(Side::A, reissued_id);
    harness.deliver(Side::B, reissued.record);
    harness.pump();

    assert_eq!(harness.take_event(Side::B), Some(Event::Opened(stream_id)));
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

    let first = harness.next_decoded_write(Side::A).unwrap();
    let id = first.write_id.expect("expected session write");

    harness.advance(config.session.retransmit_timeout + Duration::from_millis(1));
    harness.on_timer(Side::A);
    assert!(harness.next_write(Side::A).is_none());

    harness.confirm_write(Side::A, id);
    harness.advance(config.session.retransmit_timeout + Duration::from_millis(1));
    harness.on_timer(Side::A);

    let retried = harness.next_decoded_write(Side::A).unwrap();

    assert_ne!(retried.header.seq, first.header.seq);
    assert_eq!(retried.frames, first.frames);
}

#[test]
fn ack_frame_releases_stream_capacity() {
    let config = QlFsmConfig {
        session: SessionConfig {
            stream_send_buffer_size: 4,
            ..SessionConfig::default()
        },
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

    let record = harness.next_outbound(Side::A).unwrap();
    harness.deliver(Side::B, record);
    harness.advance(config.session.ack_delay);
    harness.on_timer(Side::A);
    harness.on_timer(Side::B);
    harness.pump();

    assert_eq!(harness.take_event(Side::A), None);
    assert_eq!(
        write_stream_bytes(&mut harness.a.fsm, stream_id, b"z").unwrap(),
        1
    );
}

#[test]
fn close_session_disconnects_locally() {
    let mut harness = Harness::connected(QlFsmConfig::default());
    let remote_qid = harness.b.fsm.identity.qid;

    harness
        .a
        .fsm
        .close_session(ql_wire::SessionCloseCode::CANCELLED, &harness.a.crypto);

    assert_eq!(harness.a.fsm.remote_qid(), Some(remote_qid));
    assert_eq!(harness.a.fsm.peer_status(), PeerStatus::Disconnected);
    let Some(Event::SessionClosed { close, write }) = harness.take_event(Side::A) else {
        panic!("missing session close event");
    };
    assert_eq!(close.code, ql_wire::SessionCloseCode::CANCELLED);
    let close = harness.decode_session_write(*write, Side::A);
    assert!(matches!(harness.a.fsm.state.link, LinkState::Idle));
    assert!(matches!(
        harness.a.fsm.open_stream(Box::from([1])),
        Err(NoSessionError)
    ));
    assert_eq!(harness.a.fsm.queue_ping(), Err(NoSessionError));
    assert!(matches!(
        close.frames.as_slice(),
        [ql_wire::SessionFrame::Close(_)]
    ));

    assert_eq!(harness.a.fsm.remote_qid(), Some(remote_qid));
    assert_eq!(harness.a.fsm.peer_status(), PeerStatus::Disconnected);
    assert_eq!(
        harness.take_event(Side::A),
        Some(Event::PeerStatusChanged(PeerStatus::Disconnected))
    );
}

#[test]
fn unpair_clears_bound_peer_and_emits_unpair_frame() {
    let mut harness = Harness::connected(QlFsmConfig::default());

    harness.a.fsm.unpair(&harness.a.crypto);

    assert_eq!(harness.a.fsm.remote_qid(), None);
    assert_eq!(harness.a.fsm.peer_status(), PeerStatus::Disconnected);
    let Some(Event::Unpaired { write: Some(write) }) = harness.take_event(Side::A) else {
        panic!("missing unpair event");
    };
    assert!(harness.a.fsm.peer().is_none());
    assert!(matches!(
        harness.a.fsm.open_stream(Box::from([1])),
        Err(NoSessionError)
    ));
    assert_eq!(harness.a.fsm.queue_ping(), Err(NoSessionError));

    let unpair = harness.decode_session_write(*write, Side::A);
    assert!(matches!(
        unpair.frames.as_slice(),
        [ql_wire::SessionFrame::Unpair]
    ));
    assert!(matches!(harness.a.fsm.state.link, LinkState::Idle));
    assert_eq!(harness.a.fsm.remote_qid(), None);
    assert_eq!(harness.a.fsm.peer_status(), PeerStatus::Disconnected);
    assert_eq!(
        harness.take_event(Side::A),
        Some(Event::PeerStatusChanged(PeerStatus::Unpaired))
    );
}

#[test]
fn inbound_unpair_clears_remote_peer_binding() {
    let mut harness = Harness::connected(QlFsmConfig::default());
    let reply_key = harness.a.fsm.state.link.transport().unwrap().rx_key.clone();

    harness.a.fsm.unpair(&harness.a.crypto);
    let Some(Event::Unpaired {
        write: Some(unpair),
    }) = harness.take_event(Side::A)
    else {
        panic!("missing unpair event");
    };
    assert_eq!(
        harness.take_event(Side::A),
        Some(Event::PeerStatusChanged(PeerStatus::Unpaired))
    );
    harness.deliver(Side::B, unpair.record);

    let Some(Event::Unpaired { write: Some(reply) }) = harness.take_event(Side::B) else {
        panic!("missing unpair reply");
    };
    assert_eq!(
        harness.take_event(Side::B),
        Some(Event::PeerStatusChanged(PeerStatus::Unpaired))
    );
    assert!(harness.b.fsm.peer().is_none());
    assert!(matches!(
        harness.b.fsm.open_stream(Box::from([1])),
        Err(NoSessionError)
    ));
    assert!(matches!(harness.connect_ik(Side::B), Err(NoPeerError)));

    let (_header, frames) = decrypt_record(&harness.b.crypto, &reply.record, &reply_key);
    assert!(matches!(frames.as_slice(), [ql_wire::SessionFrame::Unpair]));
    assert!(matches!(harness.b.fsm.state.link, LinkState::Idle));
}

#[test]
fn local_unpair_without_session_emits_unpaired_immediately() {
    let mut harness = Harness::paired_known(QlFsmConfig::default());

    harness.a.fsm.unpair(&harness.a.crypto);

    assert_eq!(
        harness.take_event(Side::A),
        Some(Event::Unpaired { write: None })
    );
    assert!(harness.a.fsm.peer().is_none());
    assert_eq!(harness.a.fsm.remote_qid(), None);
    assert_eq!(harness.a.fsm.peer_status(), PeerStatus::Disconnected);
    assert_eq!(
        harness.take_event(Side::A),
        Some(Event::PeerStatusChanged(PeerStatus::Unpaired))
    );
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

    let data = harness.next_outbound(Side::A).unwrap();
    harness.deliver(Side::B, data);
    harness.advance(config.session.ack_delay);
    harness.on_timer(Side::B);

    let ack = harness.next_decoded_outbound(Side::B).unwrap();
    assert!(matches!(
        ack.frames.as_slice(),
        [ql_wire::SessionFrame::Ack(_)]
    ));
}

#[test]
fn duplicate_record_is_dropped_and_not_acked() {
    let config = QlFsmConfig::default();
    let mut harness = Harness::connected(config);

    let stream_id = open_stream_id(&mut harness.a.fsm);
    assert_eq!(
        write_stream_bytes(&mut harness.a.fsm, stream_id, b"x").unwrap(),
        1
    );

    let data = harness.next_outbound(Side::A).unwrap();
    harness.deliver(Side::B, data.clone());
    harness.advance(config.session.ack_delay);
    harness.on_timer(Side::B);
    harness.next_decoded_outbound(Side::B).unwrap();

    harness.deliver(Side::B, data);
    harness.advance(config.session.ack_delay);
    harness.on_timer(Side::B);
    assert!(harness.next_outbound(Side::B).is_none());
}

#[test]
fn replayed_record_does_not_renew_the_peer_timeout() {
    let config = QlFsmConfig {
        session: SessionConfig {
            accepted_record_window: 1,
            peer_timeout: Duration::from_millis(30),
            ..SessionConfig::default()
        },
        ..QlFsmConfig::default()
    };
    let mut harness = Harness::connected(config);

    let stream_id = open_stream_id(&mut harness.a.fsm);
    assert_eq!(
        write_stream_bytes(&mut harness.a.fsm, stream_id, b"x").unwrap(),
        1
    );
    let first = harness.next_outbound(Side::A).unwrap();
    assert_eq!(
        write_stream_bytes(&mut harness.a.fsm, stream_id, b"y").unwrap(),
        1
    );
    let second = harness.next_outbound(Side::A).unwrap();

    harness.deliver(Side::B, first.clone());
    harness.deliver(Side::B, second);
    harness.drain_events(Side::B);

    harness.advance(config.session.peer_timeout);
    harness.deliver(Side::B, first);
    harness.on_timer(Side::B);

    assert!(matches!(
        harness.take_event(Side::B),
        Some(Event::SessionClosed {
            close: SessionClose {
                code: ql_wire::SessionCloseCode::TIMEOUT
            },
            ..
        })
    ));
    assert_eq!(
        harness.take_event(Side::B),
        Some(Event::PeerStatusChanged(PeerStatus::Disconnected))
    );
}

#[test]
fn first_stream_data_uses_negotiated_initial_peer_credit() {
    let mut harness = Harness::paired_known_with_configs(
        QlFsmConfig {
            session: SessionConfig {
                stream_receive_buffer_size: 8,
                ..SessionConfig::default()
            },
            ..QlFsmConfig::default()
        },
        QlFsmConfig {
            session: SessionConfig {
                stream_receive_buffer_size: 3,
                ..SessionConfig::default()
            },
            ..QlFsmConfig::default()
        },
    );

    harness.connect_ik(Side::A).unwrap();
    let ik1 = harness.next_outbound(Side::A).unwrap();
    harness.deliver(Side::B, ik1);
    let ik2 = harness.next_outbound(Side::B).unwrap();
    harness.deliver(Side::A, ik2);

    let stream_id = open_stream_id(&mut harness.a.fsm);
    assert_eq!(
        write_stream_bytes(&mut harness.a.fsm, stream_id, b"hello").unwrap(),
        5
    );

    assert!(matches!(
        harness.next_decoded_outbound(Side::A).unwrap().frames.as_slice(),
        [ql_wire::SessionFrame::StreamData(frame)] if frame.stream_id == stream_id && frame.bytes.as_slice() == b"hel"
    ));
}

#[test]
fn session_timeout_emits_close() {
    let config = QlFsmConfig {
        session: SessionConfig {
            peer_timeout: Duration::from_millis(30),
            ..SessionConfig::default()
        },
        ..QlFsmConfig::default()
    };
    let mut harness = Harness::connected(config);

    harness.advance(config.session.peer_timeout);
    harness.on_timer(Side::A);

    let Some(Event::SessionClosed { close, write }) = harness.take_event(Side::A) else {
        panic!("missing session close event");
    };
    assert_eq!(close.code, ql_wire::SessionCloseCode::TIMEOUT);
    let close = harness.decode_session_write(*write, Side::A);
    assert!(matches!(
        close.frames.as_slice(),
        [ql_wire::SessionFrame::Close(_)]
    ));
    assert_eq!(
        harness.take_event(Side::A),
        Some(Event::PeerStatusChanged(PeerStatus::Disconnected))
    );
}
