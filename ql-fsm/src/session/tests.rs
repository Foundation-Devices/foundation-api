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
    RouteId::from_u64(value).unwrap()
}

fn record_ack(seq: RecordSeq) -> RecordAck {
    RecordAck::from_ranges([seq..=seq]).unwrap()
}

const REFUSED: StreamCloseCode = StreamCloseCode(1);
const TIMEOUT: StreamCloseCode = StreamCloseCode(2);

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
    fsm.open_stream(route_id(1), |_| {}).unwrap().stream_id()
}

fn write_stream_bytes(fsm: &mut SessionFsm, stream_id: StreamId, bytes: &[u8]) -> usize {
    let mut bytes = Bytes::copy_from_slice(bytes);
    let mut stream = fsm.stream(stream_id, |_| {}).unwrap();
    let mut writer = stream.writer().unwrap();
    writer.write(&mut bytes)
}

fn read_stream_all(fsm: &mut SessionFsm, stream_id: StreamId) -> Vec<u8> {
    let mut stream = fsm.stream(stream_id, |_| {}).unwrap();
    let out = stream.read().flatten().collect::<Vec<u8>>();
    stream.commit_read(out.len()).unwrap();
    out
}

fn read_stream_all_with_events(
    fsm: &mut SessionFsm,
    stream_id: StreamId,
    events: &mut Vec<SessionEvent>,
) -> Vec<u8> {
    let mut stream = fsm.stream(stream_id, |event| events.push(event)).unwrap();
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

fn drain_outbound(
    fsm: &mut SessionFsm,
    now: Instant,
    limit: usize,
) -> Vec<(RecordSeq, Vec<SessionFrame<Vec<u8>>>)> {
    let mut records = Vec::new();
    for _ in 0..limit {
        let Some(record) = next_outbound(fsm, now) else {
            return records;
        };
        records.push(record);
    }

    panic!("session did not quiesce within outbound limit");
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
    let mut emit = |event| events.push(event);
    fsm.receive(now, seq, frames, &mut emit);
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

    let mut emit = |_| {};
    fsm.on_timer(now + Duration::from_millis(200), &mut emit);
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
    let mut emit = |event| events.push(event);
    fsm.receive(
        now + Duration::from_millis(1),
        seq(9),
        std::iter::once(Ok(SessionFrame::Ack(record_ack(record_seq)))),
        &mut emit,
    );

    assert!(events.contains(&SessionEvent::Writable(stream_id)));
    assert_eq!(write_stream_bytes(&mut fsm, stream_id, b"z"), 1);
}

#[test]
fn ack_of_fin_emits_outbound_finished_once() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionConfig::default(), now);
    let stream_id = open_stream_id(&mut fsm);

    assert_eq!(write_stream_bytes(&mut fsm, stream_id, b"done"), 4);
    fsm.stream(stream_id, |_| {})
        .unwrap()
        .writer()
        .unwrap()
        .finish();

    let (record_seq, record) = next_outbound(&mut fsm, now).unwrap();
    assert!(matches!(
        record.as_slice(),
        [SessionFrame::StreamData(StreamData {
            stream_id: id,
            fin: true,
            ..
        })] if *id == stream_id
    ));

    let mut events = Vec::new();
    {
        let mut emit = |event| events.push(event);
        fsm.receive(
            now + Duration::from_millis(1),
            seq(9),
            std::iter::once(Ok(SessionFrame::Ack(record_ack(record_seq)))),
            &mut emit,
        );
    }
    assert_eq!(events, vec![SessionEvent::OutboundFinished(stream_id)]);

    {
        let mut emit = |event| events.push(event);
        fsm.receive(
            now + Duration::from_millis(2),
            seq(10),
            std::iter::once(Ok(SessionFrame::Ack(record_ack(record_seq)))),
            &mut emit,
        );
    }
    assert_eq!(events, vec![SessionEvent::OutboundFinished(stream_id)]);
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
        .stream(stream_id, |_| {})
        .unwrap()
        .read()
        .map(|chunk| chunk.len())
        .sum::<usize>();
    assert_eq!(read, 2);

    assert!(next_outbound(&mut fsm, now + Duration::from_millis(2)).is_none());

    fsm.stream(stream_id, |_| {})
        .unwrap()
        .commit_read(2)
        .unwrap();
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

    let mut emit = |_| {};
    fsm.on_timer(
        now + retransmit_timeout + Duration::from_millis(1),
        &mut emit,
    );
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
        vec![opened(stream_id), SessionEvent::Readable(stream_id)]
    );
    let mut events = Vec::new();
    assert_eq!(
        read_stream_all_with_events(&mut fsm, stream_id, &mut events),
        b"hello".to_vec()
    );
    assert_eq!(events, vec![SessionEvent::Finished(stream_id)]);
}

#[test]
fn inbound_empty_fin_emits_finished_immediately() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionConfig::default(), now);
    let stream_id = stream_id(1);
    let record = vec![SessionFrame::StreamData(StreamData {
        stream_id,
        offset: offset(0),
        header: header(1),
        fin: true,
        bytes: Vec::new(),
    })];

    let events = receive_events(&mut fsm, now, seq(0), &record);
    assert_eq!(
        events,
        vec![opened(stream_id), SessionEvent::Finished(stream_id)]
    );
}

#[test]
fn remote_stream_close_is_reliable_and_retried() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionConfig::default(), now);
    let stream_id = open_stream_id(&mut fsm);

    fsm.stream(stream_id, |_| {})
        .unwrap()
        .close(CloseTarget::Both, StreamCloseCode::CANCELLED);

    let (write_id, builder) = fsm.take_next_write(now).unwrap();
    fsm.complete_write(now, write_id.expect("stream close should be tracked"), true);
    let first = decode_session_frames(builder.bytes()).unwrap();
    assert!(matches!(
        first.as_slice(),
        [SessionFrame::StreamClose(StreamClose { stream_id: id, .. })] if *id == stream_id
    ));

    let mut emit = |_| {};
    fsm.on_timer(now + Duration::from_millis(200), &mut emit);
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
    .open_stream(route_id(1), |_| {})
    .unwrap()
    .stream_id();
    let odd_id = SessionFsm::new(
        SessionConfig {
            local_parity: odd,
            ..SessionConfig::default()
        },
        now,
    )
    .open_stream(route_id(1), |_| {})
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
        vec![opened(stream_id), SessionEvent::Readable(stream_id)]
    );
    let mut events = Vec::new();
    assert_eq!(
        read_stream_all_with_events(&mut fsm, stream_id, &mut events),
        b"hello".to_vec()
    );
    assert_eq!(events, vec![SessionEvent::Finished(stream_id)]);

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
        vec![opened(stream_id), SessionEvent::Readable(stream_id)]
    );

    let second = receive_events(&mut fsm, now + Duration::from_millis(1), seq(2), &record);
    assert!(second.is_empty());
    let mut events = Vec::new();
    assert_eq!(
        read_stream_all_with_events(&mut fsm, stream_id, &mut events),
        b"hello".to_vec()
    );
    assert_eq!(events, vec![SessionEvent::Finished(stream_id)]);
}

#[test]
fn out_of_order_remote_stream_first_observations_still_open_once_each() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionConfig::default(), now);
    let close3 = vec![SessionFrame::StreamClose(StreamClose {
        stream_id: stream_id(3),
        target: CloseTarget::Both,
        code: REFUSED,
    })];
    let close1 = vec![SessionFrame::StreamClose(StreamClose {
        stream_id: stream_id(1),
        target: CloseTarget::Both,
        code: TIMEOUT,
    })];

    let first = receive_events(&mut fsm, now, seq(1), &close3);
    assert_eq!(
        first,
        vec![
            SessionEvent::Closed(StreamClose {
                stream_id: stream_id(3),
                target: CloseTarget::Both,
                code: REFUSED,
            }),
            SessionEvent::WritableClosed(StreamClose {
                stream_id: stream_id(3),
                target: CloseTarget::Both,
                code: REFUSED,
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
                code: TIMEOUT,
            }),
            SessionEvent::WritableClosed(StreamClose {
                stream_id: stream_id(1),
                target: CloseTarget::Both,
                code: TIMEOUT,
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
fn inbound_unpair_emits_final_unpair_frame() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionConfig::default(), now);

    let events = receive_events(&mut fsm, now, seq(1), &[SessionFrame::Unpair]);
    assert_eq!(events, vec![SessionEvent::Unpaired]);
    assert!(!fsm.is_closed());

    let (_seq, outbound) = next_outbound(&mut fsm, now + Duration::from_millis(1)).unwrap();
    assert!(matches!(outbound.as_slice(), [SessionFrame::Unpair]));
    assert!(fsm.is_closed());
}

#[test]
fn terminating_session_ignores_inbound_frames() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionConfig::default(), now);

    let mut events = Vec::new();
    fsm.unpair(&mut |event| events.push(event));
    assert_eq!(events, vec![SessionEvent::Unpaired]);

    let ignored = receive_events(
        &mut fsm,
        now + Duration::from_millis(1),
        seq(1),
        &[SessionFrame::Ping],
    );
    assert!(ignored.is_empty());

    let (_seq, outbound) = next_outbound(&mut fsm, now + Duration::from_millis(2)).unwrap();
    assert!(matches!(outbound.as_slice(), [SessionFrame::Unpair]));
    assert!(fsm.is_closed());
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

#[test]
fn sparse_out_of_order_ack_ranges_page_and_quiesce() {
    let now = Instant::now();
    let sender_config = SessionConfig {
        local_parity: StreamParity::Even,
        record_max_size: SessionRecordBuilder::MIN_CAPACITY + 40,
        ack_delay: Duration::from_millis(5),
        retransmit_timeout: Duration::from_millis(25),
        stream_send_buffer_size: 8 * 1024,
        initial_peer_stream_receive_window: 8 * 1024,
        ..SessionConfig::default()
    };
    let receiver_config = SessionConfig {
        local_parity: StreamParity::Odd,
        record_max_size: SessionRecordBuilder::MIN_CAPACITY + 10,
        ack_delay: Duration::from_millis(1),
        retransmit_timeout: Duration::from_millis(25),
        pending_ack_range_limit: 512,
        initial_peer_stream_receive_window: 8 * 1024,
        ..SessionConfig::default()
    };
    let mut sender = SessionFsm::new(sender_config, now);
    let mut receiver = SessionFsm::new(receiver_config, now);

    let stream_id = open_stream_id(&mut sender);
    let payload = vec![b'x'; 2048];
    assert_eq!(
        write_stream_bytes(&mut sender, stream_id, &payload),
        payload.len()
    );

    let originals = drain_outbound(&mut sender, now, 4096);
    assert!(originals.len() >= 64);

    for (seq, record) in originals
        .iter()
        .filter(|(seq, _)| seq.into_inner() % 2 == 1)
    {
        let _ = receive_events(&mut receiver, now, *seq, record);
    }

    let first_ack_time = now + receiver_config.ack_delay;
    let first_acks = drain_outbound(&mut receiver, first_ack_time, originals.len());
    assert!(first_acks.len() > 1);
    assert!(first_acks
        .iter()
        .all(|(_, frames)| matches!(frames.as_slice(), [SessionFrame::Ack(_)])));

    for (seq, record) in &first_acks {
        let _ = receive_events(&mut sender, first_ack_time, *seq, record);
    }

    let retransmit_time = now + sender_config.retransmit_timeout + Duration::from_millis(1);
    let mut emit = |_| {};
    sender.on_timer(retransmit_time, &mut emit);
    let retransmits = drain_outbound(&mut sender, retransmit_time, originals.len());
    assert!(!retransmits.is_empty());

    for (seq, record) in &retransmits {
        let _ = receive_events(&mut receiver, retransmit_time, *seq, record);
    }

    let second_ack_time = retransmit_time + receiver_config.ack_delay;
    let second_acks = drain_outbound(&mut receiver, second_ack_time, retransmits.len() + 16);
    assert!(!second_acks.is_empty());
    assert!(second_acks
        .iter()
        .all(|(_, frames)| matches!(frames.as_slice(), [SessionFrame::Ack(_)])));

    for (seq, record) in &second_acks {
        let _ = receive_events(&mut sender, second_ack_time, *seq, record);
    }

    let final_now = second_ack_time + sender_config.retransmit_timeout + Duration::from_millis(1);
    let mut sender_emit = |_| {};
    sender.on_timer(final_now, &mut sender_emit);
    let mut receiver_emit = |_| {};
    receiver.on_timer(final_now, &mut receiver_emit);
    assert!(next_outbound(&mut sender, final_now).is_none());
    assert!(next_outbound(&mut receiver, final_now).is_none());
}
