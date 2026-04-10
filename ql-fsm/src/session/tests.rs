use std::time::{Duration, Instant};

use bytes::Bytes;
use ql_wire::{
    decode_session_frames, parse_session_frames, CloseTarget, RecordAck, RecordSeq, RouteId,
    SessionFrame, SessionRecordBuilder, StreamClose, StreamCloseCode, StreamData, StreamHeader,
    StreamId, VarInt, XID,
};

use super::{SessionConfig, SessionEvent, SessionFsm};
use crate::session::stream_parity::StreamParity;

fn seq(value: u64) -> RecordSeq {
    RecordSeq::from_u64(value).unwrap()
}

fn stream_id(value: u64) -> StreamId {
    StreamId(VarInt::from_u64(value).unwrap())
}

fn offset(value: u64) -> VarInt {
    VarInt::from_u64(value).unwrap()
}

fn route_id(value: u64) -> RouteId {
    RouteId(VarInt::from_u64(value).unwrap())
}

fn header(value: u64) -> Option<StreamHeader> {
    Some(StreamHeader {
        route_id: route_id(value),
    })
}

fn opened(stream_id: StreamId) -> SessionEvent {
    SessionEvent::Opened {
        stream_id,
        route_id: route_id(1),
    }
}

fn open_stream_id(fsm: &mut SessionFsm) -> StreamId {
    fsm.open_stream(route_id(1)).unwrap().stream_id()
}

fn write_stream_bytes(fsm: &mut SessionFsm, stream_id: StreamId, bytes: &[u8]) -> usize {
    let mut bytes = Bytes::copy_from_slice(bytes);
    let mut stream = fsm.stream(stream_id).unwrap();
    let mut writer = stream.writer().unwrap();
    writer.write(&mut bytes)
}

fn read_stream_all(fsm: &mut SessionFsm, stream_id: StreamId) -> Vec<u8> {
    let mut stream = fsm.stream(stream_id).unwrap();
    let out = stream.read().flatten().collect::<Vec<u8>>();
    stream.commit_read(out.len()).unwrap();
    out
}

fn next_outbound(
    fsm: &mut SessionFsm,
    now: Instant,
) -> Option<(RecordSeq, Vec<SessionFrame<Vec<u8>>>)> {
    let (write_id, builder) = fsm.take_next_write(now)?;
    if let Some(write_id) = write_id {
        fsm.complete_write(now, write_id, true);
    }
    Some((
        builder.seq(),
        decode_session_frames(builder.bytes()).unwrap(),
    ))
}

fn receive_events(
    fsm: &mut SessionFsm,
    now: Instant,
    seq: RecordSeq,
    record: &[SessionFrame<Vec<u8>>],
) -> Vec<SessionEvent> {
    let mut builder = SessionRecordBuilder::new(seq, usize::MAX);
    for frame in record {
        assert!(builder.push_frame(frame));
    }
    let bytes = Bytes::from(builder.bytes().to_vec());
    let frames = parse_session_frames(bytes);
    let mut events = Vec::new();
    fsm.receive(now, seq, frames, |event| events.push(event));
    events
}

#[test]
fn outbound_record_seq_increments_monotonically() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionConfig::default(), now);
    let stream_id = open_stream_id(&mut fsm);

    assert_eq!(write_stream_bytes(&mut fsm, stream_id, b"one"), 3);
    let (first_seq, _) = next_outbound(&mut fsm, now).unwrap();

    assert_eq!(write_stream_bytes(&mut fsm, stream_id, b"two"), 3);
    let (second_seq, _) = next_outbound(&mut fsm, now + Duration::from_millis(1)).unwrap();

    assert_eq!(first_seq, seq(0));
    assert_eq!(second_seq, seq(1));
}

#[test]
fn retransmit_uses_new_record_seq() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionConfig::default(), now);
    let stream_id = open_stream_id(&mut fsm);

    assert_eq!(write_stream_bytes(&mut fsm, stream_id, b"retry"), 5);
    let (first_seq, first) = next_outbound(&mut fsm, now).unwrap();

    fsm.on_timer(now + Duration::from_millis(200), |_| {});
    let (retried_seq, retried) = next_outbound(&mut fsm, now + Duration::from_millis(200)).unwrap();

    assert_ne!(first_seq, retried_seq);
    assert_eq!(first, retried);
}

#[test]
fn lost_record_on_one_stream_does_not_block_another_stream() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(
        SessionConfig {
            record_max_size: 80 + SessionRecordBuilder::MIN_CAPACITY,
            ..SessionConfig::default()
        },
        now,
    );
    let stream_id_a = open_stream_id(&mut fsm);
    let stream_id_b = open_stream_id(&mut fsm);
    let payload_a = vec![b'a'; 40];
    let payload_b = vec![b'b'; 40];

    assert_eq!(write_stream_bytes(&mut fsm, stream_id_a, &payload_a), 40);
    assert_eq!(write_stream_bytes(&mut fsm, stream_id_b, &payload_b), 40);

    let (first_seq, first) = next_outbound(&mut fsm, now).unwrap();
    let (second_seq, _second) = next_outbound(&mut fsm, now + Duration::from_millis(1)).unwrap();
    assert_ne!(first_seq, second_seq);
    assert!(first.iter().any(
        |frame| matches!(frame, SessionFrame::StreamData(frame) if frame.stream_id == stream_id_a)
    ));

    assert_eq!(write_stream_bytes(&mut fsm, stream_id_b, b"b-2"), 3);
    let (_third_seq, third) = next_outbound(&mut fsm, now + Duration::from_millis(2)).unwrap();

    let stream_ids: Vec<_> = third
        .iter()
        .filter_map(|frame| match frame {
            SessionFrame::StreamData(frame) => Some(frame.stream_id),
            _ => None,
        })
        .collect();
    assert_eq!(stream_ids, vec![stream_id_b]);
}

#[test]
fn ack_reopens_write_capacity() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(
        SessionConfig {
            stream_send_buffer_size: 4,
            ..SessionConfig::default()
        },
        now,
    );
    let stream_id = open_stream_id(&mut fsm);

    assert_eq!(write_stream_bytes(&mut fsm, stream_id, b"abcd"), 4);
    let (record_seq, _record) = next_outbound(&mut fsm, now).unwrap();

    let mut events = Vec::new();
    fsm.receive(
        now + Duration::from_millis(1),
        seq(9),
        std::iter::once(Ok(SessionFrame::Ack(RecordAck {
            base_seq: record_seq,
            bits: 1u64,
        }))),
        |event| events.push(event),
    );

    assert!(events.contains(&SessionEvent::Writable(stream_id)));
    assert_eq!(write_stream_bytes(&mut fsm, stream_id, b"z"), 1);
}

#[test]
fn commit_stream_read_is_what_advances_stream_window() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(
        SessionConfig {
            local_parity: StreamParity::Even,
            ack_delay: Duration::ZERO,
            ..SessionConfig::default()
        },
        now,
    );
    let stream_id = stream_id(1);
    let data = vec![SessionFrame::StreamData(StreamData {
        stream_id,
        offset: offset(0),
        header: header(1),
        fin: false,
        bytes: b"hi".to_vec(),
    })];
    let events = receive_events(&mut fsm, now, seq(7), &data);
    assert_eq!(
        events,
        vec![opened(stream_id), SessionEvent::Readable(stream_id)]
    );

    let (write_id, builder) = fsm.take_next_write(now + Duration::from_millis(1)).unwrap();
    let first = decode_session_frames(builder.bytes()).unwrap();
    assert!(write_id.is_none());
    assert!(matches!(first.as_slice(), [SessionFrame::Ack(_)]));

    let read = fsm
        .stream(stream_id)
        .unwrap()
        .read()
        .map(|chunk| chunk.len())
        .sum::<usize>();
    assert_eq!(read, 2);

    assert!(next_outbound(&mut fsm, now + Duration::from_millis(2)).is_none());

    fsm.stream(stream_id).unwrap().commit_read(2).unwrap();
    let (_second_seq, second) = next_outbound(&mut fsm, now + Duration::from_millis(3)).unwrap();
    assert!(matches!(
        second.as_slice(),
        [SessionFrame::StreamWindow(window)] if window.stream_id == stream_id
    ));
}

#[test]
fn pure_ack_only_records_are_fire_and_forget() {
    let now = Instant::now();
    let config = SessionConfig {
        ack_delay: Duration::ZERO,
        ..SessionConfig::default()
    };
    let retransmit_timeout = config.retransmit_timeout;
    let mut fsm = SessionFsm::new(config, now);
    let stream_id = stream_id(1);
    let record = vec![SessionFrame::StreamData(StreamData {
        stream_id,
        offset: offset(0),
        header: header(1),
        fin: false,
        bytes: b"hi".to_vec(),
    })];

    let _ = receive_events(&mut fsm, now, seq(7), &record);

    let (write_id, builder) = fsm.take_next_write(now + Duration::from_millis(1)).unwrap();
    let ack = decode_session_frames(builder.bytes()).unwrap();
    assert!(write_id.is_none());
    assert!(matches!(ack.as_slice(), [SessionFrame::Ack(_)]));

    fsm.on_timer(now + retransmit_timeout + Duration::from_millis(1), |_| {});
    assert!(fsm
        .take_next_write(now + retransmit_timeout + Duration::from_millis(1))
        .is_none());
}

#[test]
fn inbound_stream_data_emits_opened_and_readable() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionConfig::default(), now);
    let stream_id = stream_id(1);
    let record = vec![SessionFrame::StreamData(ql_wire::StreamData {
        stream_id,
        offset: offset(0),
        header: header(1),
        fin: true,
        bytes: b"hello".to_vec(),
    })];

    let events = receive_events(&mut fsm, now, seq(0), &record);
    assert_eq!(
        events,
        vec![
            opened(stream_id),
            SessionEvent::Readable(stream_id),
            SessionEvent::Finished(stream_id)
        ]
    );
    assert_eq!(read_stream_all(&mut fsm, stream_id), b"hello".to_vec());
}

#[test]
fn remote_stream_close_is_reliable_and_retried() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionConfig::default(), now);
    let stream_id = open_stream_id(&mut fsm);

    fsm.stream(stream_id)
        .unwrap()
        .close(CloseTarget::Both, StreamCloseCode(0));

    let (write_id, builder) = fsm.take_next_write(now).unwrap();
    fsm.complete_write(now, write_id.expect("stream close should be tracked"), true);
    let first = decode_session_frames(builder.bytes()).unwrap();
    assert!(matches!(
        first.as_slice(),
        [SessionFrame::StreamClose(StreamClose { stream_id: id, .. })] if *id == stream_id
    ));

    fsm.on_timer(now + Duration::from_millis(200), |_| {});
    let (_retried_seq, retried) =
        next_outbound(&mut fsm, now + Duration::from_millis(200)).unwrap();
    assert_eq!(first, retried);
}

#[test]
fn stream_ids_follow_even_odd_xid_ordering() {
    let now = Instant::now();
    let even = StreamParity::for_local(XID([1; XID::SIZE]), XID([2; XID::SIZE]));
    let odd = StreamParity::for_local(XID([2; XID::SIZE]), XID([1; XID::SIZE]));

    let even_id = SessionFsm::new(
        SessionConfig {
            local_parity: even,
            ..SessionConfig::default()
        },
        now,
    )
    .open_stream(route_id(1))
    .unwrap()
    .stream_id();
    let odd_id = SessionFsm::new(
        SessionConfig {
            local_parity: odd,
            ..SessionConfig::default()
        },
        now,
    )
    .open_stream(route_id(1))
    .unwrap()
    .stream_id();

    assert_eq!(even_id.into_inner() % 2, 0);
    assert_eq!(odd_id.into_inner() % 2, 1);
}

#[test]
fn duplicate_stream_data_is_not_redelivered() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionConfig::default(), now);
    let stream_id = stream_id(1);
    let record = vec![SessionFrame::StreamData(StreamData {
        stream_id,
        offset: offset(0),
        header: header(1),
        fin: false,
        bytes: b"hi".to_vec(),
    })];
    let _ = receive_events(&mut fsm, now, seq(1), &record);
    let _ = receive_events(&mut fsm, now + Duration::from_millis(1), seq(2), &record);

    assert_eq!(read_stream_all(&mut fsm, stream_id), b"hi".to_vec());
}

#[test]
fn duplicate_remote_close_after_reap_is_ignored() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionConfig::default(), now);
    let close = StreamClose {
        stream_id: stream_id(1),
        target: CloseTarget::Both,
        code: StreamCloseCode(9),
    };
    let record = vec![SessionFrame::StreamClose(close.clone())];

    let first = receive_events(&mut fsm, now, seq(1), &record);
    assert_eq!(
        first,
        vec![
            SessionEvent::Closed(close.clone()),
            SessionEvent::WritableClosed(close),
        ]
    );

    let second = receive_events(&mut fsm, now + Duration::from_millis(1), seq(2), &record);
    assert!(second.is_empty());
}

#[test]
fn late_remote_stream_data_after_close_is_ignored() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionConfig::default(), now);
    let stream_id = stream_id(1);
    let close = vec![SessionFrame::StreamClose(StreamClose {
        stream_id,
        target: CloseTarget::Both,
        code: StreamCloseCode(9),
    })];
    let data = vec![SessionFrame::StreamData(StreamData {
        stream_id,
        offset: offset(0),
        header: header(1),
        fin: false,
        bytes: b"hello".to_vec(),
    })];

    let first = receive_events(&mut fsm, now, seq(1), &close);
    assert_eq!(
        first,
        vec![
            SessionEvent::Closed(StreamClose {
                stream_id,
                target: CloseTarget::Both,
                code: StreamCloseCode(9),
            }),
            SessionEvent::WritableClosed(StreamClose {
                stream_id,
                target: CloseTarget::Both,
                code: StreamCloseCode(9),
            }),
        ]
    );

    let second = receive_events(&mut fsm, now + Duration::from_millis(1), seq(2), &data);
    assert!(second.is_empty());
}

#[test]
fn duplicate_finished_remote_data_after_reap_is_ignored() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionConfig::default(), now);
    let stream_id = stream_id(1);
    let record = vec![SessionFrame::StreamData(StreamData {
        stream_id,
        offset: offset(0),
        header: header(1),
        fin: true,
        bytes: b"hello".to_vec(),
    })];

    let first = receive_events(&mut fsm, now, seq(1), &record);
    assert_eq!(
        first,
        vec![
            opened(stream_id),
            SessionEvent::Readable(stream_id),
            SessionEvent::Finished(stream_id),
        ]
    );
    assert_eq!(read_stream_all(&mut fsm, stream_id), b"hello".to_vec());

    let second = receive_events(&mut fsm, now + Duration::from_millis(1), seq(2), &record);
    assert!(second.is_empty());
}

#[test]
fn duplicate_finished_remote_data_before_read_is_ignored() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionConfig::default(), now);
    let stream_id = stream_id(1);
    let record = vec![SessionFrame::StreamData(StreamData {
        stream_id,
        offset: offset(0),
        header: header(1),
        fin: true,
        bytes: b"hello".to_vec(),
    })];

    let first = receive_events(&mut fsm, now, seq(1), &record);
    assert_eq!(
        first,
        vec![
            opened(stream_id),
            SessionEvent::Readable(stream_id),
            SessionEvent::Finished(stream_id),
        ]
    );

    let second = receive_events(&mut fsm, now + Duration::from_millis(1), seq(2), &record);
    assert!(second.is_empty());
    assert_eq!(read_stream_all(&mut fsm, stream_id), b"hello".to_vec());
}

#[test]
fn out_of_order_remote_stream_first_observations_still_open_once_each() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionConfig::default(), now);
    let close3 = vec![SessionFrame::StreamClose(StreamClose {
        stream_id: stream_id(3),
        target: CloseTarget::Both,
        code: StreamCloseCode(1),
    })];
    let close1 = vec![SessionFrame::StreamClose(StreamClose {
        stream_id: stream_id(1),
        target: CloseTarget::Both,
        code: StreamCloseCode(2),
    })];

    let first = receive_events(&mut fsm, now, seq(1), &close3);
    assert_eq!(
        first,
        vec![
            SessionEvent::Closed(StreamClose {
                stream_id: stream_id(3),
                target: CloseTarget::Both,
                code: StreamCloseCode(1),
            }),
            SessionEvent::WritableClosed(StreamClose {
                stream_id: stream_id(3),
                target: CloseTarget::Both,
                code: StreamCloseCode(1),
            }),
        ]
    );

    let second = receive_events(&mut fsm, now + Duration::from_millis(1), seq(2), &close1);
    assert_eq!(
        second,
        vec![
            SessionEvent::Closed(StreamClose {
                stream_id: stream_id(1),
                target: CloseTarget::Both,
                code: StreamCloseCode(2),
            }),
            SessionEvent::WritableClosed(StreamClose {
                stream_id: stream_id(1),
                target: CloseTarget::Both,
                code: StreamCloseCode(2),
            }),
        ]
    );

    let third = receive_events(&mut fsm, now + Duration::from_millis(2), seq(3), &close3);
    assert!(third.is_empty());
}

#[test]
fn invalid_remote_stream_close_closes_session() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionConfig::default(), now);

    let invalid = vec![SessionFrame::StreamClose(StreamClose {
        stream_id: stream_id(0),
        target: CloseTarget::Both,
        code: StreamCloseCode(9),
    })];
    let events = receive_events(&mut fsm, now, seq(1), &invalid);

    assert_eq!(
        events,
        vec![SessionEvent::SessionClosed(ql_wire::SessionClose {
            code: ql_wire::SessionCloseCode::PROTOCOL,
        })]
    );
}

#[test]
fn close_does_not_ack_rejected_record_seq() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(
        SessionConfig {
            ack_delay: Duration::ZERO,
            ..SessionConfig::default()
        },
        now,
    );

    let invalid = vec![SessionFrame::StreamData(StreamData {
        stream_id: stream_id(0),
        offset: offset(0),
        header: header(1),
        fin: false,
        bytes: b"bad".to_vec(),
    })];
    let events = receive_events(&mut fsm, now, seq(7), &invalid);
    assert_eq!(
        events,
        vec![SessionEvent::SessionClosed(ql_wire::SessionClose {
            code: ql_wire::SessionCloseCode::PROTOCOL,
        })]
    );

    let valid_after_close = vec![SessionFrame::Ping];
    let events = receive_events(
        &mut fsm,
        now + Duration::from_millis(1),
        seq(8),
        &valid_after_close,
    );
    assert!(events.is_empty());

    let (_seq, outbound) = next_outbound(&mut fsm, now + Duration::from_millis(2)).unwrap();
    assert!(matches!(outbound.as_slice(), [SessionFrame::Close(_)]));
}

#[test]
fn initial_peer_stream_receive_window_limits_first_send() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(
        SessionConfig {
            initial_peer_stream_receive_window: 3,
            ..SessionConfig::default()
        },
        now,
    );
    let stream_id = open_stream_id(&mut fsm);

    assert_eq!(write_stream_bytes(&mut fsm, stream_id, b"hello"), 5);
    let (_first_seq, first) = next_outbound(&mut fsm, now).unwrap();
    assert!(matches!(
        first.as_slice(),
        [SessionFrame::StreamData(frame)] if frame.stream_id == stream_id && frame.bytes.as_slice() == b"hel"
    ));

    let events = receive_events(
        &mut fsm,
        now + Duration::from_millis(1),
        seq(9),
        &[SessionFrame::StreamWindow(ql_wire::StreamWindow {
            stream_id,
            maximum_offset: offset(5),
        })],
    );
    assert!(events.is_empty());

    let (_second_seq, second) = next_outbound(&mut fsm, now + Duration::from_millis(2)).unwrap();
    assert!(second.iter().any(|frame| {
        matches!(
            frame,
            SessionFrame::StreamData(frame)
                if frame.stream_id == stream_id
                    && frame.offset == offset(3)
                    && frame.bytes.as_slice() == b"lo"
        )
    }));
}
