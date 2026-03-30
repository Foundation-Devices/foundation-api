use std::time::{Duration, Instant};

use ql_wire::{
    CloseTarget, RecordAck, RecordAckRange, RecordSeq, SessionFrame, SessionRecord, StreamClose,
    StreamCloseCode, StreamData, StreamId, XID,
};

use super::{state::StreamParity, SessionEvent, SessionFsm, SessionFsmConfig};

fn read_stream_all(fsm: &mut SessionFsm, stream_id: StreamId) -> Vec<u8> {
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

fn next_outbound(fsm: &mut SessionFsm, now: Instant) -> Option<(RecordSeq, SessionRecord)> {
    let (write_id, seq, builder) = fsm.take_next_write(now)?;
    fsm.confirm_write(now, write_id);
    Some((seq, SessionRecord::decode(builder.bytes()).unwrap()))
}

fn receive_events(fsm: &mut SessionFsm, now: Instant, seq: RecordSeq, record: SessionRecord) -> Vec<SessionEvent> {
    let bytes = record.encode();
    let frames = SessionRecord::parse(&bytes).unwrap();
    let mut events = Vec::new();
    fsm.receive(now, seq, frames, |event| events.push(event));
    events
}

#[test]
fn outbound_record_seq_increments_monotonically() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_id = fsm.open_stream().unwrap();

    assert_eq!(fsm.write_stream(stream_id, b"one").unwrap(), 3);
    let (first_seq, _) = next_outbound(&mut fsm, now).unwrap();

    assert_eq!(fsm.write_stream(stream_id, b"two").unwrap(), 3);
    let (second_seq, _) = next_outbound(&mut fsm, now + Duration::from_millis(1)).unwrap();

    assert_eq!(first_seq, RecordSeq(0));
    assert_eq!(second_seq, RecordSeq(1));
}

#[test]
fn retransmit_uses_new_record_seq() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_id = fsm.open_stream().unwrap();

    assert_eq!(fsm.write_stream(stream_id, b"retry").unwrap(), 5);
    let (first_seq, first) = next_outbound(&mut fsm, now).unwrap();

    fsm.on_timer(now + Duration::from_millis(200), |_| {});
    let (retried_seq, retried) = next_outbound(&mut fsm, now + Duration::from_millis(200)).unwrap();

    assert_ne!(first_seq, retried_seq);
    assert_eq!(first.frames, retried.frames);
}

#[test]
fn lost_record_on_one_stream_does_not_block_another_stream() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(
        SessionFsmConfig {
            record_size: 80,
            ..SessionFsmConfig::default()
        },
        now,
    );
    let stream_id_a = fsm.open_stream().unwrap();
    let stream_id_b = fsm.open_stream().unwrap();
    let payload_a = vec![b'a'; 40];
    let payload_b = vec![b'b'; 40];

    assert_eq!(fsm.write_stream(stream_id_a, &payload_a).unwrap(), 40);
    assert_eq!(fsm.write_stream(stream_id_b, &payload_b).unwrap(), 40);

    let (first_seq, first) = next_outbound(&mut fsm, now).unwrap();
    let (second_seq, _second) = next_outbound(&mut fsm, now + Duration::from_millis(1)).unwrap();
    assert_ne!(first_seq, second_seq);
    assert!(first
        .frames
        .iter()
        .any(|frame| matches!(frame, SessionFrame::StreamData(frame) if frame.stream_id == stream_id_a)));

    assert_eq!(fsm.write_stream(stream_id_b, b"b-2").unwrap(), 3);
    let (_third_seq, third) = next_outbound(&mut fsm, now + Duration::from_millis(2)).unwrap();

    let stream_ids: Vec<_> = third
        .frames
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
        SessionFsmConfig {
            stream_send_buffer_size: 4,
            ..SessionFsmConfig::default()
        },
        now,
    );
    let stream_id = fsm.open_stream().unwrap();

    assert_eq!(fsm.write_stream(stream_id, b"abcd").unwrap(), 4);
    let (seq, _record) = next_outbound(&mut fsm, now).unwrap();

    let mut events = Vec::new();
    fsm.receive(
        now + Duration::from_millis(1),
        RecordSeq(9),
        std::iter::once(Ok(SessionFrame::Ack(RecordAck {
            ranges: vec![RecordAckRange {
                start: seq.0,
                end: seq.0 + 1,
            }],
        }))),
        |event| events.push(event),
    );

    assert!(events.contains(&SessionEvent::Writable(stream_id)));
    assert_eq!(fsm.write_stream(stream_id, b"z").unwrap(), 1);
}

#[test]
fn commit_stream_read_is_what_advances_stream_window() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(
        SessionFsmConfig {
            local_parity: StreamParity::Even,
            ack_delay: Duration::ZERO,
            ..SessionFsmConfig::default()
        },
        now,
    );
    let stream_id = StreamId(1);
    let data = SessionRecord {
        frames: vec![SessionFrame::StreamData(StreamData {
            stream_id,
            offset: 0,
            fin: false,
            bytes: b"hi".to_vec(),
        })],
    };
    let events = receive_events(&mut fsm, now, RecordSeq(7), data);
    assert_eq!(
        events,
        vec![
            SessionEvent::Opened(stream_id),
            SessionEvent::Readable(stream_id)
        ]
    );

    let (_first_seq, first) = next_outbound(&mut fsm, now + Duration::from_millis(1)).unwrap();
    assert!(matches!(first.frames.as_slice(), [SessionFrame::Ack(_)]));

    let read = fsm
        .stream_read(stream_id)
        .unwrap()
        .map(|chunk| chunk.len())
        .sum::<usize>();
    assert_eq!(read, 2);

    assert!(next_outbound(&mut fsm, now + Duration::from_millis(2)).is_none());

    fsm.stream_read_commit(stream_id, 2).unwrap();
    let (_second_seq, second) = next_outbound(&mut fsm, now + Duration::from_millis(3)).unwrap();
    assert!(matches!(
        second.frames.as_slice(),
        [SessionFrame::StreamWindow(window)] if window.stream_id == stream_id
    ));
}

#[test]
fn inbound_stream_data_emits_opened_and_readable() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_id = ql_wire::StreamId(1);
    let record = SessionRecord {
        frames: vec![SessionFrame::StreamData(ql_wire::StreamData {
            stream_id,
            offset: 0,
            fin: true,
            bytes: b"hello".to_vec(),
        })],
    };

    let events = receive_events(&mut fsm, now, RecordSeq(0), record);
    assert_eq!(
        events,
        vec![
            SessionEvent::Opened(stream_id),
            SessionEvent::Readable(stream_id),
            SessionEvent::Finished(stream_id)
        ]
    );
    assert_eq!(read_stream_all(&mut fsm, stream_id), b"hello".to_vec());
}

#[test]
fn remote_stream_close_is_reliable_and_retried() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_id = fsm.open_stream().unwrap();

    fsm.close_stream(stream_id, CloseTarget::Both, StreamCloseCode(0))
        .unwrap();

    let (write_id, _seq, builder) = fsm.take_next_write(now).unwrap();
    fsm.confirm_write(now, write_id);
    let first = SessionRecord::decode(builder.bytes()).unwrap();
    assert!(matches!(
        first.frames.as_slice(),
        [SessionFrame::StreamClose(StreamClose { stream_id: id, .. })] if *id == stream_id
    ));

    fsm.on_timer(now + Duration::from_millis(200), |_| {});
    let (_retried_seq, retried) = next_outbound(&mut fsm, now + Duration::from_millis(200)).unwrap();
    assert_eq!(first.frames, retried.frames);
}

#[test]
fn stream_ids_follow_even_odd_xid_ordering() {
    let now = Instant::now();
    let even = StreamParity::for_local(XID([1; XID::SIZE]), XID([2; XID::SIZE]));
    let odd = StreamParity::for_local(XID([2; XID::SIZE]), XID([1; XID::SIZE]));

    let even_id = SessionFsm::new(
        SessionFsmConfig {
            local_parity: even,
            ..SessionFsmConfig::default()
        },
        now,
    )
    .open_stream()
    .unwrap();
    let odd_id = SessionFsm::new(
        SessionFsmConfig {
            local_parity: odd,
            ..SessionFsmConfig::default()
        },
        now,
    )
    .open_stream()
    .unwrap();

    assert_eq!(even_id.0 % 2, 0);
    assert_eq!(odd_id.0 % 2, 1);
}

#[test]
fn duplicate_stream_data_is_not_redelivered() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_id = StreamId(1);
    let record = SessionRecord {
        frames: vec![SessionFrame::StreamData(StreamData {
            stream_id,
            offset: 0,
            fin: false,
            bytes: b"hi".to_vec(),
        })],
    };
    let _ = receive_events(&mut fsm, now, RecordSeq(1), record.clone());
    let _ = receive_events(&mut fsm, now + Duration::from_millis(1), RecordSeq(2), record);

    assert_eq!(read_stream_all(&mut fsm, stream_id), b"hi".to_vec());
}
