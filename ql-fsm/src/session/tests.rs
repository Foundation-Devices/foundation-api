use std::time::{Duration, Instant};

use bytes::Bytes;
use ql_codec::Varint;
use ql_common::{ResetCode, StreamId, QID};
use ql_wire::{
    decode_session_frames, parse_session_frames, RecordAck, RecordSeq, ResetTarget, SessionFrame,
    SessionRecordBuilder, StreamData, StreamReset,
};

use super::{
    state::{InboundState, OutboundState},
    SessionConfig, SessionEvent, SessionParams,
};
use crate::{
    session::stream_parity::StreamParity, ReaderState, StreamIo, StreamMeta, StreamResetEvent,
    WriterState,
};

const REFUSED: ResetCode = ResetCode(1);
const TIMEOUT: ResetCode = ResetCode(2);

#[derive(Default)]
struct TestMeta {
    readable: usize,
    writable: usize,
    consume_reads: bool,
    read: Vec<u8>,
    pending_write: Bytes,
    inbound_finished: usize,
    outbound_finished: usize,
    resets: Vec<StreamResetEvent>,
}

impl StreamMeta for TestMeta {
    fn on_readable(&mut self, mut stream: StreamIo<'_>) {
        self.readable += 1;
        if self.consume_reads {
            let mut reader = stream.reader().active().unwrap();
            let bytes = reader.read().flatten().collect::<Vec<_>>();
            reader.commit_read(bytes.len()).unwrap();
            self.read.extend(bytes);
        }
    }

    fn on_writable(&mut self, mut stream: StreamIo<'_>) {
        self.writable += 1;
        if let Some(mut writer) = stream.writer().active() {
            writer.write(&mut self.pending_write);
        }
    }

    fn on_inbound_finished(&mut self, _stream: StreamIo<'_>) {
        self.inbound_finished += 1;
    }

    fn on_outbound_finished(&mut self, _stream_id: StreamId) {
        self.outbound_finished += 1;
    }

    fn on_reset(&mut self, reset: StreamResetEvent) {
        self.resets.push(reset);
    }
}

fn open_stream_id(fsm: &mut super::SessionFsm<()>) -> StreamId {
    fsm.open_stream(Box::from([1])).io().stream_id()
}

fn write_stream_bytes(fsm: &mut super::SessionFsm<()>, stream_id: StreamId, bytes: &[u8]) -> usize {
    let mut bytes = Bytes::copy_from_slice(bytes);
    let mut stream = fsm.stream(stream_id).unwrap();
    let mut io = stream.io();
    let mut writer = io.writer().active().unwrap();
    writer.write(&mut bytes)
}

fn read_stream_all(fsm: &mut super::SessionFsm<()>, stream_id: StreamId) -> Vec<u8> {
    let mut stream = fsm.stream(stream_id).unwrap();
    let mut io = stream.io();
    let mut reader = io.reader().active().unwrap();
    let out = reader.read().flatten().collect::<Vec<u8>>();
    reader.commit_read(out.len()).unwrap();
    out
}

fn next_outbound<M: StreamMeta>(
    fsm: &mut super::SessionFsm<M>,
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
    fsm: &mut super::SessionFsm<()>,
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

fn receive_events<M: StreamMeta>(
    fsm: &mut super::SessionFsm<M>,
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
    let mut fsm =
        super::SessionFsm::<()>::new(SessionConfig::default(), SessionParams::default(), now);
    let stream_id = open_stream_id(&mut fsm);

    assert_eq!(write_stream_bytes(&mut fsm, stream_id, b"one"), 3);
    let (first_seq, _) = next_outbound(&mut fsm, now).unwrap();

    assert_eq!(write_stream_bytes(&mut fsm, stream_id, b"two"), 3);
    let (second_seq, _) = next_outbound(&mut fsm, now + Duration::from_millis(1)).unwrap();

    assert_eq!(first_seq, RecordSeq(0));
    assert_eq!(second_seq, RecordSeq(1));
}

#[test]
fn stream_data_is_scheduled_round_robin() {
    let now = Instant::now();
    let config = SessionConfig::default();
    let payload = vec![b'x'; config.stream_send_buffer_size];
    let mut fsm = super::SessionFsm::<()>::new(config, SessionParams::default(), now);
    let a = open_stream_id(&mut fsm);
    let b = open_stream_id(&mut fsm);
    let c = open_stream_id(&mut fsm);
    let d = open_stream_id(&mut fsm);
    for stream_id in [a, c, d] {
        assert_eq!(
            write_stream_bytes(&mut fsm, stream_id, &payload),
            payload.len()
        );
    }
    let next_stream_id = |fsm: &mut super::SessionFsm<()>| {
        let (_, frames) = next_outbound(fsm, now).unwrap();
        let [SessionFrame::StreamData(frame)] = frames.as_slice() else {
            panic!("expected one stream data frame, got {frames:?}");
        };
        frame.stream_id
    };

    assert_eq!(next_stream_id(&mut fsm), a);

    let stream = fsm.state.streams.get_mut(&b).unwrap();
    stream.io.inbound_state = InboundState::Finished;
    stream.io.outbound_state = OutboundState::Finished;
    fsm.reap_reapable_streams();
    assert!(fsm.stream(b).is_err());

    for expected in [c, d, a] {
        assert_eq!(next_stream_id(&mut fsm), expected);
    }
}

#[test]
fn retransmit_uses_new_record_seq() {
    let now = Instant::now();
    let mut fsm = super::SessionFsm::<()>::new(
        SessionConfig {
            retransmit_timeout: Duration::from_millis(100),
            ..SessionConfig::default()
        },
        SessionParams::default(),
        now,
    );
    let stream_id = open_stream_id(&mut fsm);

    assert_eq!(write_stream_bytes(&mut fsm, stream_id, b"retry"), 5);
    let (first_seq, first) = next_outbound(&mut fsm, now).unwrap();

    let mut emit = |_| {};
    fsm.on_timer(now + Duration::from_millis(101), &mut emit);
    let (retried_seq, retried) = next_outbound(&mut fsm, now + Duration::from_millis(101)).unwrap();

    assert_ne!(first_seq, retried_seq);
    assert_eq!(first, retried);
}

#[test]
fn retransmitted_record_ack_releases_stream_data() {
    let now = Instant::now();
    let mut fsm = super::SessionFsm::<()>::new(
        SessionConfig {
            retransmit_timeout: Duration::from_millis(20),
            stream_send_buffer_size: 4,
            ..SessionConfig::default()
        },
        SessionParams::default(),
        now,
    );
    let stream_id = open_stream_id(&mut fsm);

    assert_eq!(write_stream_bytes(&mut fsm, stream_id, b"data"), 4);
    let (first_seq, _) = next_outbound(&mut fsm, now).unwrap();

    let mut emit = |_| {};
    fsm.on_timer(now + Duration::from_millis(21), &mut emit);
    let (retried_seq, _) = next_outbound(&mut fsm, now + Duration::from_millis(21)).unwrap();
    assert_ne!(first_seq, retried_seq);

    let mut events = Vec::new();
    fsm.receive(
        now + Duration::from_millis(22),
        RecordSeq(9),
        std::iter::once(Ok(SessionFrame::Ack(
            RecordAck::from_ranges([retried_seq..=retried_seq]).unwrap(),
        ))),
        &mut |event| events.push(event),
    );

    assert!(events.is_empty());
    assert_eq!(write_stream_bytes(&mut fsm, stream_id, b"z"), 1);
}

#[test]
fn acknowledged_rtt_updates_retransmit_timeout() {
    let now = Instant::now();
    let mut fsm = super::SessionFsm::<()>::new(
        SessionConfig {
            retransmit_timeout: Duration::from_millis(100),
            ..SessionConfig::default()
        },
        SessionParams::default(),
        now,
    );
    let stream_id = open_stream_id(&mut fsm);

    assert_eq!(write_stream_bytes(&mut fsm, stream_id, b"first"), 5);
    let (first_seq, _) = next_outbound(&mut fsm, now).unwrap();
    fsm.receive(
        now + Duration::from_millis(80),
        RecordSeq(9),
        std::iter::once(Ok(SessionFrame::Ack(
            RecordAck::from_ranges([first_seq..=first_seq]).unwrap(),
        ))),
        &mut |_| {},
    );

    assert_eq!(write_stream_bytes(&mut fsm, stream_id, b"second"), 6);
    next_outbound(&mut fsm, now + Duration::from_millis(80)).unwrap();

    let mut emit = |_| {};
    fsm.on_timer(now + Duration::from_millis(181), &mut emit);
    assert!(next_outbound(&mut fsm, now + Duration::from_millis(181)).is_none());

    fsm.on_timer(now + Duration::from_millis(321), &mut emit);
    assert!(next_outbound(&mut fsm, now + Duration::from_millis(321)).is_some());
}

#[test]
fn retransmit_timeout_backs_off() {
    let now = Instant::now();
    let mut fsm = super::SessionFsm::<()>::new(
        SessionConfig {
            retransmit_timeout: Duration::from_millis(20),
            ..SessionConfig::default()
        },
        SessionParams::default(),
        now,
    );
    let stream_id = open_stream_id(&mut fsm);

    assert_eq!(write_stream_bytes(&mut fsm, stream_id, b"retry"), 5);
    next_outbound(&mut fsm, now).unwrap();

    let mut emit = |_| {};
    fsm.on_timer(now + Duration::from_millis(21), &mut emit);
    next_outbound(&mut fsm, now + Duration::from_millis(21)).unwrap();

    fsm.on_timer(now + Duration::from_millis(42), &mut emit);
    assert!(next_outbound(&mut fsm, now + Duration::from_millis(42)).is_none());

    fsm.on_timer(now + Duration::from_millis(62), &mut emit);
    assert!(next_outbound(&mut fsm, now + Duration::from_millis(62)).is_some());
}

#[test]
fn tracked_record_count_is_bounded() {
    const PAYLOAD_LEN: usize = 1024;

    let now = Instant::now();
    let mut fsm = super::SessionFsm::<()>::new(
        SessionConfig {
            record_max_size: SessionRecordBuilder::MIN_CAPACITY
                + 1
                + StreamData::<Vec<u8>>::MAX_WIRE_OVERHEAD
                + 1,
            stream_send_buffer_size: PAYLOAD_LEN,
            ..SessionConfig::default()
        },
        SessionParams {
            initial_stream_receive_window: PAYLOAD_LEN as u32,
            ..SessionParams::default()
        },
        now,
    );
    let stream_id = open_stream_id(&mut fsm);
    assert_eq!(
        write_stream_bytes(&mut fsm, stream_id, &[b'x'; PAYLOAD_LEN]),
        PAYLOAD_LEN
    );

    let mut count = 0;
    while next_outbound(&mut fsm, now).is_some() {
        count += 1;
        assert!(count <= 64);
    }

    assert_eq!(count, 64);
    assert_eq!(fsm.state.tracked_records.len(), 64);
}

#[test]
fn lost_record_on_one_stream_does_not_block_another_stream() {
    const PAYLOAD_LEN: usize = 40;

    let now = Instant::now();
    let mut fsm = super::SessionFsm::<()>::new(
        SessionConfig {
            record_max_size: SessionRecordBuilder::MIN_CAPACITY
                + 1 // discriminator byte
                + StreamData::<Vec<u8>>::MAX_WIRE_OVERHEAD
                + PAYLOAD_LEN,
            ..SessionConfig::default()
        },
        SessionParams::default(),
        now,
    );
    let stream_id_a = open_stream_id(&mut fsm);
    let stream_id_b = open_stream_id(&mut fsm);
    let payload_a = vec![b'a'; PAYLOAD_LEN];
    let payload_b = vec![b'b'; PAYLOAD_LEN];

    assert_eq!(
        write_stream_bytes(&mut fsm, stream_id_a, &payload_a),
        PAYLOAD_LEN
    );
    assert_eq!(
        write_stream_bytes(&mut fsm, stream_id_b, &payload_b),
        PAYLOAD_LEN
    );

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
    let mut fsm = super::SessionFsm::<TestMeta>::new(
        SessionConfig {
            stream_send_buffer_size: 4,
            ..SessionConfig::default()
        },
        SessionParams::default(),
        now,
    );
    let stream_id = fsm.open_stream(Box::from([1])).io().stream_id();

    let mut bytes = Bytes::from_static(b"abcd");
    let mut stream = fsm.stream(stream_id).unwrap();
    assert_eq!(stream.io().writer().active().unwrap().write(&mut bytes), 4);
    stream.metadata_mut().pending_write = Bytes::from_static(b"z");
    drop(stream);
    let (record_seq, _record) = next_outbound(&mut fsm, now).unwrap();

    let mut events = Vec::new();
    let mut emit = |event| events.push(event);
    fsm.receive(
        now + Duration::from_millis(1),
        RecordSeq(9),
        std::iter::once(Ok(SessionFrame::Ack(
            RecordAck::from_ranges([record_seq..=record_seq]).unwrap(),
        ))),
        &mut emit,
    );

    assert!(events.is_empty());
    let mut stream = fsm.stream(stream_id).unwrap();
    assert_eq!(stream.metadata().writable, 1);
    assert!(stream.metadata().pending_write.is_empty());
    assert_eq!(stream.io().writer().active().unwrap().capacity(), 3);
}

#[test]
fn ack_of_fin_notifies_metadata_once() {
    let now = Instant::now();
    let mut fsm =
        super::SessionFsm::<TestMeta>::new(SessionConfig::default(), SessionParams::default(), now);
    let stream_id = fsm.open_stream(Box::from([1])).io().stream_id();

    let mut bytes = Bytes::from_static(b"done");
    let mut stream = fsm.stream(stream_id).unwrap();
    assert_eq!(stream.io().writer().active().unwrap().write(&mut bytes), 4);
    stream.io().writer().active().unwrap().finish();
    drop(stream);

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
            RecordSeq(9),
            std::iter::once(Ok(SessionFrame::Ack(
                RecordAck::from_ranges([record_seq..=record_seq]).unwrap(),
            ))),
            &mut emit,
        );
    }
    assert!(events.is_empty());
    assert_eq!(fsm.state.streams[&stream_id].metadata.outbound_finished, 1);

    {
        let mut emit = |event| events.push(event);
        fsm.receive(
            now + Duration::from_millis(2),
            RecordSeq(10),
            std::iter::once(Ok(SessionFrame::Ack(
                RecordAck::from_ranges([record_seq..=record_seq]).unwrap(),
            ))),
            &mut emit,
        );
    }
    assert!(events.is_empty());
    assert_eq!(fsm.state.streams[&stream_id].metadata.outbound_finished, 1);
}

#[test]
fn commit_stream_read_is_what_advances_stream_window() {
    let now = Instant::now();
    let mut fsm = super::SessionFsm::<()>::new(
        SessionConfig {
            ack_delay: Duration::ZERO,
            ..SessionConfig::default()
        },
        SessionParams {
            local_parity: StreamParity::Even,
            ..SessionParams::default()
        },
        now,
    );
    let stream_id = StreamId(1);
    let data = vec![SessionFrame::StreamData(StreamData {
        stream_id,
        offset: Varint(0),
        header: Some(vec![1_u8]),
        fin: false,
        bytes: b"hi".to_vec(),
    })];
    let events = receive_events(&mut fsm, now, RecordSeq(7), &data);
    assert_eq!(events, vec![SessionEvent::Opened(stream_id)]);

    let (write_id, builder) = fsm.take_next_write(now + Duration::from_millis(1)).unwrap();
    let first = decode_session_frames(builder.bytes()).unwrap();
    assert!(write_id.is_none());
    assert!(matches!(first.as_slice(), [SessionFrame::Ack(_)]));

    let read = fsm
        .stream(stream_id)
        .unwrap()
        .io()
        .reader()
        .active()
        .unwrap()
        .read()
        .map(|chunk| chunk.len())
        .sum::<usize>();
    assert_eq!(read, 2);

    assert!(next_outbound(&mut fsm, now + Duration::from_millis(2)).is_none());

    fsm.stream(stream_id)
        .unwrap()
        .io()
        .reader()
        .active()
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
fn lost_stream_window_is_resent_after_a_timeout() {
    let now = Instant::now();
    let mut fsm = super::SessionFsm::<()>::new(
        SessionConfig {
            ack_delay: Duration::ZERO,
            retransmit_timeout: Duration::from_millis(20),
            ..SessionConfig::default()
        },
        SessionParams::default(),
        now,
    );
    let stream_id = StreamId(1);
    let data = vec![SessionFrame::StreamData(StreamData {
        stream_id,
        offset: Varint(0),
        header: Some(vec![1_u8]),
        fin: false,
        bytes: b"hi".to_vec(),
    })];
    receive_events(&mut fsm, now, RecordSeq(7), &data);
    next_outbound(&mut fsm, now + Duration::from_millis(1)).unwrap();

    read_stream_all(&mut fsm, stream_id);
    let (_first_seq, first) = next_outbound(&mut fsm, now + Duration::from_millis(2)).unwrap();
    let [SessionFrame::StreamWindow(sent)] = first.as_slice() else {
        panic!("expected a window update, got {first:?}");
    };
    let sent_offset = *sent.maximum_offset;

    let mut emit = |_| {};
    fsm.on_timer(now + Duration::from_millis(23), &mut emit);

    let (_resent_seq, resent) = next_outbound(&mut fsm, now + Duration::from_millis(23)).unwrap();
    assert!(matches!(
        resent.as_slice(),
        [SessionFrame::StreamWindow(window)]
            if window.stream_id == stream_id && *window.maximum_offset == sent_offset
    ));
}

#[test]
fn lost_ping_is_resent_after_a_timeout() {
    let now = Instant::now();
    let mut fsm = super::SessionFsm::<()>::new(
        SessionConfig {
            keepalive_interval: Duration::ZERO,
            retransmit_timeout: Duration::from_millis(20),
            ..SessionConfig::default()
        },
        SessionParams::default(),
        now,
    );

    fsm.queue_ping();
    let (_first_seq, first) = next_outbound(&mut fsm, now).unwrap();
    assert!(matches!(first.as_slice(), [SessionFrame::Ping]));

    let mut emit = |_| {};
    fsm.on_timer(now + Duration::from_millis(21), &mut emit);

    let (_resent_seq, resent) = next_outbound(&mut fsm, now + Duration::from_millis(21)).unwrap();
    assert!(matches!(resent.as_slice(), [SessionFrame::Ping]));
}

#[test]
fn pure_ack_only_records_are_fire_and_forget() {
    let now = Instant::now();
    let config = SessionConfig {
        ack_delay: Duration::ZERO,
        ..SessionConfig::default()
    };
    let retransmit_timeout = config.retransmit_timeout;
    let mut fsm = super::SessionFsm::<()>::new(config, SessionParams::default(), now);
    let stream_id = StreamId(1);
    let record = vec![SessionFrame::StreamData(StreamData {
        stream_id,
        offset: Varint(0),
        header: Some(vec![1_u8]),
        fin: false,
        bytes: b"hi".to_vec(),
    })];

    let _ = receive_events(&mut fsm, now, RecordSeq(7), &record);

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
fn inbound_stream_data_queues_opened_and_notifies_metadata() {
    let now = Instant::now();
    let mut fsm =
        super::SessionFsm::<TestMeta>::new(SessionConfig::default(), SessionParams::default(), now);
    let stream_id = StreamId(1);
    let record = vec![SessionFrame::StreamData(ql_wire::StreamData {
        stream_id,
        offset: Varint(0),
        header: Some(vec![1_u8]),
        fin: true,
        bytes: b"hello".to_vec(),
    })];

    let events = receive_events(&mut fsm, now, RecordSeq(0), &record);
    assert_eq!(events, vec![SessionEvent::Opened(stream_id)]);
    let mut stream = fsm.stream(stream_id).unwrap();
    assert_eq!(stream.metadata().readable, 1);
    assert_eq!(stream.metadata().inbound_finished, 1);
    {
        let mut io = stream.io();
        assert!(matches!(io.reader(), ReaderState::Final(_)));
        let mut reader = io.reader().active().unwrap();
        let bytes = reader.read().flatten().collect::<Vec<_>>();
        assert_eq!(bytes, b"hello");
        reader.commit_read(bytes.len()).unwrap();
    }
    drop(stream);
    let mut stream = fsm.stream(stream_id).unwrap();
    assert_eq!(stream.metadata().inbound_finished, 1);
    assert!(stream.io().reader().active().is_none());
}

#[test]
fn readable_callback_can_consume_stream_data() {
    let now = Instant::now();
    let mut fsm =
        super::SessionFsm::<TestMeta>::new(SessionConfig::default(), SessionParams::default(), now);
    let stream_id = fsm.open_stream(Box::from([1])).io().stream_id();
    fsm.stream(stream_id).unwrap().metadata_mut().consume_reads = true;
    let record = [SessionFrame::StreamData(StreamData {
        stream_id,
        offset: Varint(0),
        header: None,
        fin: true,
        bytes: b"hello".to_vec(),
    })];

    assert!(receive_events(&mut fsm, now, RecordSeq(0), &record).is_empty());
    let mut stream = fsm.stream(stream_id).unwrap();
    assert_eq!(stream.metadata().readable, 1);
    assert_eq!(stream.metadata().read, b"hello");
    assert_eq!(stream.metadata().inbound_finished, 1);
    assert!(stream.io().reader().active().is_none());
    assert!(matches!(stream.io().reader(), ReaderState::Finished));
}

#[test]
fn inbound_empty_fin_notifies_metadata_immediately() {
    let now = Instant::now();
    let mut fsm =
        super::SessionFsm::<TestMeta>::new(SessionConfig::default(), SessionParams::default(), now);
    let stream_id = StreamId(1);
    let record = vec![SessionFrame::StreamData(StreamData {
        stream_id,
        offset: Varint(0),
        header: Some(vec![1_u8]),
        fin: true,
        bytes: Vec::new(),
    })];

    let events = receive_events(&mut fsm, now, RecordSeq(0), &record);
    assert_eq!(events, vec![SessionEvent::Opened(stream_id)]);
    let mut stream = fsm.stream(stream_id).unwrap();
    assert!(matches!(stream.io().reader(), ReaderState::Finished));
    assert_eq!(stream.metadata().inbound_finished, 1);
}

#[test]
fn local_stream_reset_is_reliable_and_notifies_metadata() {
    let now = Instant::now();
    let mut fsm = super::SessionFsm::<TestMeta>::new(
        SessionConfig {
            retransmit_timeout: Duration::from_millis(100),
            ..SessionConfig::default()
        },
        SessionParams::default(),
        now,
    );
    let stream_id = fsm.open_stream(Box::from([1])).io().stream_id();

    fsm.stream(stream_id)
        .unwrap()
        .reset(crate::StreamResetTarget::Both, ResetCode::CANCELLED);
    assert_eq!(
        fsm.stream(stream_id).unwrap().metadata().resets,
        vec![StreamResetEvent {
            stream_id,
            code: ResetCode::CANCELLED,
            target: crate::StreamResetTarget::Both,
            origin: crate::ResetOrigin::Local,
        }]
    );

    let (write_id, builder) = fsm.take_next_write(now).unwrap();
    fsm.complete_write(now, write_id.expect("stream reset should be tracked"), true);
    let first = decode_session_frames(builder.bytes()).unwrap();
    assert!(matches!(
        first.as_slice(),
        [SessionFrame::StreamReset(StreamReset { stream_id: id, .. })] if *id == stream_id
    ));

    let mut emit = |_| {};
    fsm.on_timer(now + Duration::from_millis(101), &mut emit);
    let (_retried_seq, retried) =
        next_outbound(&mut fsm, now + Duration::from_millis(101)).unwrap();
    assert_eq!(first, retried);
}

#[test]
fn stream_ids_follow_even_odd_xid_ordering() {
    let now = Instant::now();
    let even = StreamParity::for_local(QID([1; QID::SIZE]), QID([2; QID::SIZE]));
    let odd = StreamParity::for_local(QID([2; QID::SIZE]), QID([1; QID::SIZE]));

    let even_id = super::SessionFsm::<()>::new(
        SessionConfig::default(),
        SessionParams {
            local_parity: even,
            ..SessionParams::default()
        },
        now,
    )
    .open_stream(vec![1_u8].into_boxed_slice())
    .io()
    .stream_id();
    let odd_id = super::SessionFsm::<()>::new(
        SessionConfig::default(),
        SessionParams {
            local_parity: odd,
            ..SessionParams::default()
        },
        now,
    )
    .open_stream(vec![1_u8].into_boxed_slice())
    .io()
    .stream_id();

    assert_eq!(even_id.0 % 2, 0);
    assert_eq!(odd_id.0 % 2, 1);
}

#[test]
fn duplicate_stream_data_is_not_redelivered() {
    let now = Instant::now();
    let mut fsm =
        super::SessionFsm::<()>::new(SessionConfig::default(), SessionParams::default(), now);
    let stream_id = StreamId(1);
    let record = vec![SessionFrame::StreamData(StreamData {
        stream_id,
        offset: Varint(0),
        header: Some(vec![1_u8]),
        fin: false,
        bytes: b"hi".to_vec(),
    })];
    let _ = receive_events(&mut fsm, now, RecordSeq(1), &record);
    let _ = receive_events(
        &mut fsm,
        now + Duration::from_millis(1),
        RecordSeq(2),
        &record,
    );

    assert_eq!(read_stream_all(&mut fsm, stream_id), b"hi".to_vec());
}

#[test]
fn duplicate_remote_reset_after_reap_is_ignored() {
    let now = Instant::now();
    let mut fsm =
        super::SessionFsm::<()>::new(SessionConfig::default(), SessionParams::default(), now);
    let reset = StreamReset {
        stream_id: StreamId(1),
        target: ResetTarget::Both,
        code: ResetCode(9),
    };
    let record = vec![SessionFrame::StreamReset(reset.clone())];

    let first = receive_events(&mut fsm, now, RecordSeq(1), &record);
    assert!(first.is_empty());
    assert!(fsm.stream(reset.stream_id).is_err());

    let second = receive_events(
        &mut fsm,
        now + Duration::from_millis(1),
        RecordSeq(2),
        &record,
    );
    assert!(second.is_empty());
}

#[test]
fn late_remote_stream_data_after_reset_is_ignored() {
    let now = Instant::now();
    let mut fsm =
        super::SessionFsm::<()>::new(SessionConfig::default(), SessionParams::default(), now);
    let stream_id = StreamId(1);
    let reset = vec![SessionFrame::StreamReset(StreamReset {
        stream_id,
        target: ResetTarget::Both,
        code: ResetCode(9),
    })];
    let data = vec![SessionFrame::StreamData(StreamData {
        stream_id,
        offset: Varint(0),
        header: Some(vec![1_u8]),
        fin: false,
        bytes: b"hello".to_vec(),
    })];

    let first = receive_events(&mut fsm, now, RecordSeq(1), &reset);
    assert!(first.is_empty());

    let second = receive_events(
        &mut fsm,
        now + Duration::from_millis(1),
        RecordSeq(2),
        &data,
    );
    assert!(second.is_empty());
}

#[test]
fn stream_reset_in_its_opening_record_leaves_stale_events() {
    let now = Instant::now();
    let mut fsm =
        super::SessionFsm::<()>::new(SessionConfig::default(), SessionParams::default(), now);
    let stream_id = StreamId(1);
    let record = [
        SessionFrame::StreamData(StreamData {
            stream_id,
            offset: Varint(0),
            header: Some(vec![1_u8]),
            fin: false,
            bytes: b"discarded".to_vec(),
        }),
        SessionFrame::StreamReset(StreamReset {
            stream_id,
            target: ResetTarget::Both,
            code: REFUSED,
        }),
    ];

    assert_eq!(
        receive_events(&mut fsm, now, RecordSeq(1), &record),
        vec![SessionEvent::Opened(stream_id)]
    );
    assert!(fsm.stream(stream_id).is_err());
}

#[test]
fn one_sided_remote_reset_notifies_metadata_and_preserves_stream() {
    let now = Instant::now();
    let mut fsm =
        super::SessionFsm::<TestMeta>::new(SessionConfig::default(), SessionParams::default(), now);
    let stream_id = StreamId(1);
    let data = [SessionFrame::StreamData(StreamData {
        stream_id,
        offset: Varint(0),
        header: Some(vec![1_u8]),
        fin: false,
        bytes: b"discarded".to_vec(),
    })];
    let reset = [SessionFrame::StreamReset(StreamReset {
        stream_id,
        target: ResetTarget::Origin,
        code: REFUSED,
    })];

    assert_eq!(
        receive_events(&mut fsm, now, RecordSeq(1), &data),
        vec![SessionEvent::Opened(stream_id)]
    );
    assert!(receive_events(&mut fsm, now, RecordSeq(2), &reset).is_empty());

    let mut stream = fsm.stream(stream_id).unwrap();
    assert!(matches!(stream.io().reader(), ReaderState::Reset(REFUSED)));
    assert!(matches!(stream.io().writer(), WriterState::Open(_)));
    assert!(stream.io().reader().active().is_none());
    assert_eq!(
        stream.metadata().resets,
        vec![StreamResetEvent {
            stream_id,
            code: REFUSED,
            target: crate::StreamResetTarget::Reader,
            origin: crate::ResetOrigin::Peer,
        }]
    );
}

#[test]
fn draining_the_last_bytes_reaps_a_terminal_stream_on_drop() {
    let now = Instant::now();
    let mut fsm =
        super::SessionFsm::<TestMeta>::new(SessionConfig::default(), SessionParams::default(), now);
    let stream_id = StreamId(1);
    let record = [
        SessionFrame::StreamData(StreamData {
            stream_id,
            offset: Varint(0),
            header: Some(vec![1_u8]),
            fin: true,
            bytes: b"hello".to_vec(),
        }),
        SessionFrame::StreamReset(StreamReset {
            stream_id,
            target: ResetTarget::Return,
            code: REFUSED,
        }),
    ];

    assert_eq!(
        receive_events(&mut fsm, now, RecordSeq(1), &record),
        vec![SessionEvent::Opened(stream_id)]
    );
    let mut stream = fsm.stream(stream_id).unwrap();
    {
        let mut io = stream.io();
        let mut reader = io.reader().active().unwrap();
        let bytes = reader.read().flatten().collect::<Vec<_>>();
        assert_eq!(bytes, b"hello");
        reader.commit_read(bytes.len()).unwrap();
    }
    drop(stream);

    assert!(fsm.stream(stream_id).is_err());
}

#[test]
fn duplicate_finished_remote_data_after_read_is_ignored() {
    let now = Instant::now();
    let mut fsm =
        super::SessionFsm::<()>::new(SessionConfig::default(), SessionParams::default(), now);
    let stream_id = StreamId(1);
    let record = vec![SessionFrame::StreamData(StreamData {
        stream_id,
        offset: Varint(0),
        header: Some(vec![1_u8]),
        fin: true,
        bytes: b"hello".to_vec(),
    })];

    let first = receive_events(&mut fsm, now, RecordSeq(1), &record);
    assert_eq!(first, vec![SessionEvent::Opened(stream_id)]);
    assert_eq!(read_stream_all(&mut fsm, stream_id), b"hello".to_vec());

    let second = receive_events(
        &mut fsm,
        now + Duration::from_millis(1),
        RecordSeq(2),
        &record,
    );
    assert!(second.is_empty());
}

#[test]
fn duplicate_finished_remote_data_before_read_is_ignored() {
    let now = Instant::now();
    let mut fsm =
        super::SessionFsm::<()>::new(SessionConfig::default(), SessionParams::default(), now);
    let stream_id = StreamId(1);
    let record = vec![SessionFrame::StreamData(StreamData {
        stream_id,
        offset: Varint(0),
        header: Some(vec![1_u8]),
        fin: true,
        bytes: b"hello".to_vec(),
    })];

    let first = receive_events(&mut fsm, now, RecordSeq(1), &record);
    assert_eq!(first, vec![SessionEvent::Opened(stream_id)]);

    let second = receive_events(
        &mut fsm,
        now + Duration::from_millis(1),
        RecordSeq(2),
        &record,
    );
    assert!(second.is_empty());
    assert_eq!(read_stream_all(&mut fsm, stream_id), b"hello".to_vec());
}

#[test]
fn out_of_order_remote_stream_first_observations_still_open_once_each() {
    let now = Instant::now();
    let mut fsm =
        super::SessionFsm::<()>::new(SessionConfig::default(), SessionParams::default(), now);
    let reset3 = vec![SessionFrame::StreamReset(StreamReset {
        stream_id: StreamId(3),
        target: ResetTarget::Both,
        code: REFUSED,
    })];
    let reset1 = vec![SessionFrame::StreamReset(StreamReset {
        stream_id: StreamId(1),
        target: ResetTarget::Both,
        code: TIMEOUT,
    })];

    let first = receive_events(&mut fsm, now, RecordSeq(1), &reset3);
    assert!(first.is_empty());

    let second = receive_events(
        &mut fsm,
        now + Duration::from_millis(1),
        RecordSeq(2),
        &reset1,
    );
    assert!(second.is_empty());

    let third = receive_events(
        &mut fsm,
        now + Duration::from_millis(2),
        RecordSeq(3),
        &reset3,
    );
    assert!(third.is_empty());
}

#[test]
fn invalid_remote_stream_reset_closes_session() {
    let now = Instant::now();
    let mut fsm =
        super::SessionFsm::<()>::new(SessionConfig::default(), SessionParams::default(), now);

    let invalid = vec![SessionFrame::StreamReset(StreamReset {
        stream_id: StreamId(0),
        target: ResetTarget::Both,
        code: ResetCode(9),
    })];
    let events = receive_events(&mut fsm, now, RecordSeq(1), &invalid);

    let [SessionEvent::SessionClosed { close, write }] = events.as_slice() else {
        panic!("expected session close event");
    };
    assert_eq!(close.code, ql_wire::SessionCloseCode::PROTOCOL);
    assert!(matches!(
        decode_session_frames(write.bytes()).unwrap().as_slice(),
        [SessionFrame::Close(_)]
    ));
}

#[test]
fn close_does_not_ack_rejected_record_seq() {
    let now = Instant::now();
    let mut fsm = super::SessionFsm::<()>::new(
        SessionConfig {
            ack_delay: Duration::ZERO,
            ..SessionConfig::default()
        },
        SessionParams::default(),
        now,
    );

    let invalid = vec![SessionFrame::StreamData(StreamData {
        stream_id: StreamId(0),
        offset: Varint(0),
        header: Some(vec![1_u8]),
        fin: false,
        bytes: b"bad".to_vec(),
    })];
    let events = receive_events(&mut fsm, now, RecordSeq(7), &invalid);
    let [SessionEvent::SessionClosed { close, write }] = events.as_slice() else {
        panic!("expected session close event");
    };
    assert_eq!(close.code, ql_wire::SessionCloseCode::PROTOCOL);
    assert!(matches!(
        decode_session_frames(write.bytes()).unwrap().as_slice(),
        [SessionFrame::Close(_)]
    ));
}

#[test]
fn inbound_unpair_closes_session() {
    let now = Instant::now();
    let mut fsm =
        super::SessionFsm::<()>::new(SessionConfig::default(), SessionParams::default(), now);

    let events = receive_events(&mut fsm, now, RecordSeq(1), &[SessionFrame::Unpair]);
    let [SessionEvent::Unpaired { write }] = events.as_slice() else {
        panic!("expected unpaired event");
    };
    assert!(matches!(
        decode_session_frames(write.bytes()).unwrap().as_slice(),
        [SessionFrame::Unpair]
    ));
}

#[test]
fn initial_peer_stream_receive_window_limits_first_send() {
    let now = Instant::now();
    let mut fsm = super::SessionFsm::<()>::new(
        SessionConfig::default(),
        SessionParams {
            initial_stream_receive_window: 3,
            ..SessionParams::default()
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
        RecordSeq(9),
        &[SessionFrame::StreamWindow(ql_wire::StreamWindow {
            stream_id,
            maximum_offset: Varint(5),
        })],
    );
    assert!(events.is_empty());

    let (_second_seq, second) = next_outbound(&mut fsm, now + Duration::from_millis(2)).unwrap();
    assert!(second.iter().any(|frame| {
        matches!(
            frame,
            SessionFrame::StreamData(frame)
                if frame.stream_id == stream_id
                    && *frame.offset == 3
                    && frame.bytes.as_slice() == b"lo"
        )
    }));
}

#[test]
fn sparse_out_of_order_ack_ranges_page_and_quiesce() {
    let now = Instant::now();
    let sender_config = SessionConfig {
        record_max_size: SessionRecordBuilder::MIN_CAPACITY
            + 1 // discriminator byte
            + StreamData::<Vec<u8>>::MAX_WIRE_OVERHEAD
            + 10, // keeps stream-data records tiny enough to force ACK paging
        ack_delay: Duration::from_millis(5),
        retransmit_timeout: Duration::from_millis(25),
        stream_send_buffer_size: 8 * 1024,
        ..SessionConfig::default()
    };
    let receiver_config = SessionConfig {
        record_max_size: SessionRecordBuilder::MIN_CAPACITY + 10,
        ack_delay: Duration::from_millis(1),
        retransmit_timeout: Duration::from_millis(25),
        pending_ack_range_limit: 512,
        ..SessionConfig::default()
    };
    let params = |local_parity| SessionParams {
        local_parity,
        initial_stream_receive_window: 8 * 1024,
    };
    let mut sender = super::SessionFsm::<()>::new(sender_config, params(StreamParity::Even), now);
    let mut receiver =
        super::SessionFsm::<()>::new(receiver_config, params(StreamParity::Odd), now);

    let stream_id = open_stream_id(&mut sender);
    let payload = vec![b'x'; 1200];
    assert_eq!(
        write_stream_bytes(&mut sender, stream_id, &payload),
        payload.len()
    );

    let originals = drain_outbound(&mut sender, now, 4096);
    assert_eq!(originals.len(), 64);

    for (seq, record) in originals.iter().filter(|(seq, _)| seq.0 % 2 == 1) {
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

#[test]
fn stream_header_larger_than_the_record_budget_does_not_panic() {
    let now = Instant::now();
    let record_max_size = SessionRecordBuilder::MIN_CAPACITY + 256;
    let mut fsm = super::SessionFsm::<()>::new(
        SessionConfig {
            record_max_size,
            ..SessionConfig::default()
        },
        SessionParams::default(),
        now,
    );

    // The header rides in the same frame as the payload, so one this large leaves no room.
    let stream_id = fsm.open_stream(Box::from(vec![7u8; 256])).io().stream_id();
    assert_eq!(write_stream_bytes(&mut fsm, stream_id, b"payload"), 7);

    assert!(next_outbound(&mut fsm, now).is_none());
}
