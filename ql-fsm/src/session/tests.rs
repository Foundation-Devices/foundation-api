use std::time::{Duration, Instant};

use ql_wire::{
    CloseCode, CloseTarget, PingBody, SessionAck, SessionBody, SessionEnvelope, SessionSeq,
    StreamChunk, StreamClose,
};

use super::{SessionFsm, SessionFsmConfig, SessionState};

fn read_stream_all(fsm: &mut SessionFsm, stream_id: ql_wire::StreamId) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 64];
    loop {
        let read = fsm.read_stream(stream_id, &mut buf).unwrap();
        if read == 0 {
            break;
        }
        out.extend_from_slice(&buf[..read]);
    }
    out
}

fn ack(seq: u64, ack: SessionAck) -> SessionEnvelope {
    SessionEnvelope {
        seq: SessionSeq(seq),
        ack,
        body: SessionBody::Ack,
    }
}

fn ping(seq: u64, ack: SessionAck) -> SessionEnvelope {
    SessionEnvelope {
        seq: SessionSeq(seq),
        ack,
        body: SessionBody::Ping(PingBody),
    }
}

fn next_outbound(fsm: &mut SessionFsm, now: Instant) -> Option<SessionEnvelope> {
    let envelope = fsm.take_next_write(now)?;
    fsm.confirm_write(now, envelope.seq);
    Some(envelope)
}

#[test]
fn outbound_session_seq_increments_monotonically() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_id = fsm.open_stream().unwrap();

    fsm.write_stream(stream_id, b"one".to_vec()).unwrap();
    let first = next_outbound(&mut fsm, now).unwrap();

    fsm.receive(
        now + Duration::from_millis(1),
        ack(
            1,
            SessionAck {
                base: SessionSeq(1),
                bitmap: 0,
            },
        ),
    );

    fsm.write_stream(stream_id, b"two".to_vec()).unwrap();
    let second = next_outbound(&mut fsm, now + Duration::from_millis(2)).unwrap();

    assert_eq!(first.seq, SessionSeq(1));
    assert_eq!(second.seq, SessionSeq(2));
}

#[test]
fn inbound_ack_removes_acked_tx_entries() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_id = fsm.open_stream().unwrap();

    fsm.write_stream(stream_id, b"one".to_vec()).unwrap();
    let first = next_outbound(&mut fsm, now).unwrap();
    assert_eq!(first.seq, SessionSeq(1));
    assert!(fsm.state.tx_ring.contains_key(&SessionSeq(1)));

    fsm.receive(
        now + Duration::from_millis(1),
        ack(
            1,
            SessionAck {
                base: SessionSeq(1),
                bitmap: 0,
            },
        ),
    );

    assert!(!fsm.state.tx_ring.contains_key(&SessionSeq(1)));
}

#[test]
fn out_of_order_receive_produces_bitmap_ack_then_advances_base() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_id_a = ql_wire::StreamId(super::StreamNamespace::High.bit() | 1);
    let stream_id_b = ql_wire::StreamId(super::StreamNamespace::High.bit() | 2);

    fsm.receive(
        now,
        SessionEnvelope {
            seq: SessionSeq(2),
            ack: SessionAck::EMPTY,
            body: SessionBody::Stream(StreamChunk {
                stream_id: stream_id_a,
                offset: 0,
                bytes: b"a".to_vec(),
                fin: false,
            }),
        },
    );
    let gap_ack = next_outbound(&mut fsm, now).unwrap();
    assert_eq!(gap_ack.seq, SessionSeq(1));
    assert_eq!(
        gap_ack.ack,
        SessionAck {
            base: SessionSeq(0),
            bitmap: 0b10,
        }
    );

    fsm.receive(
        now + Duration::from_millis(1),
        SessionEnvelope {
            seq: SessionSeq(1),
            ack: SessionAck::EMPTY,
            body: SessionBody::Stream(StreamChunk {
                stream_id: stream_id_b,
                offset: 0,
                bytes: b"b".to_vec(),
                fin: false,
            }),
        },
    );
    let contiguous_ack = next_outbound(&mut fsm, now + Duration::from_millis(10)).unwrap();
    assert_eq!(contiguous_ack.seq, SessionSeq(2));
    assert_eq!(
        contiguous_ack.ack,
        SessionAck {
            base: SessionSeq(2),
            bitmap: 0,
        }
    );
}

#[test]
fn retransmit_reuses_session_seq() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_id = fsm.open_stream().unwrap();

    fsm.write_stream(stream_id, b"retry-me".to_vec()).unwrap();
    let first = next_outbound(&mut fsm, now).unwrap();

    let retransmit_at = now + Duration::from_millis(200);
    let retried = next_outbound(&mut fsm, retransmit_at).unwrap();

    assert_eq!(first.seq, SessionSeq(1));
    assert_eq!(retried.seq, SessionSeq(1));
    assert_eq!(retried.body, first.body);
}

#[test]
fn repeated_outbound_messages_keep_reporting_latest_receive_ack() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_id_a = fsm.open_stream().unwrap();
    let stream_id_b = fsm.open_stream().unwrap();

    fsm.receive(now, ack(1, SessionAck::EMPTY));

    fsm.write_stream(stream_id_a, b"one".to_vec()).unwrap();
    let first = next_outbound(&mut fsm, now).unwrap();

    fsm.write_stream(stream_id_b, b"two".to_vec()).unwrap();
    let second = next_outbound(&mut fsm, now + Duration::from_millis(1)).unwrap();

    assert_eq!(first.ack.base, SessionSeq(1));
    assert_eq!(second.ack.base, SessionSeq(1));
    assert_eq!(first.ack.bitmap, 0);
    assert_eq!(second.ack.bitmap, 0);
}

#[test]
fn local_inbound_close_ignores_late_remote_bytes() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_id = fsm.open_stream().unwrap();

    fsm.close_stream(
        stream_id,
        CloseTarget::Response,
        CloseCode::CANCELLED,
        Vec::new(),
    )
    .unwrap();

    fsm.receive(
        now,
        SessionEnvelope {
            seq: SessionSeq(1),
            ack: SessionAck::EMPTY,
            body: SessionBody::Stream(StreamChunk {
                stream_id,
                offset: 0,
                bytes: b"late".to_vec(),
                fin: false,
            }),
        },
    );

    assert_eq!(fsm.state.session_state, SessionState::Open);
    assert_eq!(read_stream_all(&mut fsm, stream_id), Vec::<u8>::new());
    assert!(fsm.take_next_event().is_none());
}

#[test]
fn missing_stream_nonzero_offset_is_ignored_until_offset_zero_arrives() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_id = ql_wire::StreamId(super::StreamNamespace::High.bit() | 7);

    fsm.receive(
        now,
        SessionEnvelope {
            seq: SessionSeq(1),
            ack: SessionAck::EMPTY,
            body: SessionBody::Stream(StreamChunk {
                stream_id,
                offset: 1,
                bytes: b"b".to_vec(),
                fin: false,
            }),
        },
    );

    assert_eq!(fsm.state.session_state, SessionState::Open);
    assert!(fsm.take_next_event().is_none());
    assert!(!fsm.state.streams.contains_key(&stream_id));

    fsm.receive(
        now + Duration::from_millis(1),
        SessionEnvelope {
            seq: SessionSeq(2),
            ack: SessionAck::EMPTY,
            body: SessionBody::Stream(StreamChunk {
                stream_id,
                offset: 0,
                bytes: b"a".to_vec(),
                fin: false,
            }),
        },
    );

    assert_eq!(
        fsm.take_next_event(),
        Some(super::SessionEvent::Opened(stream_id))
    );
    assert_eq!(
        fsm.take_next_event(),
        Some(super::SessionEvent::Readable(stream_id))
    );
    assert_eq!(read_stream_all(&mut fsm, stream_id), b"a".to_vec());
}

#[test]
fn local_stream_waits_for_open_frame_ack_before_sending_follow_up_data() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(
        SessionFsmConfig {
            stream_chunk_size: 2,
            ..SessionFsmConfig::default()
        },
        now,
    );
    let stream_id = fsm.open_stream().unwrap();

    fsm.write_stream(stream_id, b"hello".to_vec()).unwrap();

    let first = next_outbound(&mut fsm, now).unwrap();
    assert_eq!(
        first.body,
        SessionBody::Stream(StreamChunk {
            stream_id,
            offset: 0,
            bytes: b"he".to_vec(),
            fin: false,
        })
    );
    assert!(next_outbound(&mut fsm, now + Duration::from_millis(1)).is_none());

    fsm.receive(
        now + Duration::from_millis(2),
        ack(
            1,
            SessionAck {
                base: SessionSeq(1),
                bitmap: 0,
            },
        ),
    );

    let second = next_outbound(&mut fsm, now + Duration::from_millis(3)).unwrap();
    assert_eq!(
        second.body,
        SessionBody::Stream(StreamChunk {
            stream_id,
            offset: 2,
            bytes: b"ll".to_vec(),
            fin: false,
        })
    );
}

#[test]
fn stream_is_reaped_after_terminal_state_and_last_stream_ack() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_id = ql_wire::StreamId(super::StreamNamespace::High.bit() | 13);

    fsm.receive(
        now,
        SessionEnvelope {
            seq: SessionSeq(1),
            ack: SessionAck::EMPTY,
            body: SessionBody::Stream(StreamChunk {
                stream_id,
                offset: 0,
                bytes: b"hi".to_vec(),
                fin: true,
            }),
        },
    );

    assert_eq!(
        fsm.take_next_event(),
        Some(super::SessionEvent::Opened(stream_id))
    );
    assert_eq!(
        fsm.take_next_event(),
        Some(super::SessionEvent::Readable(stream_id))
    );
    assert_eq!(read_stream_all(&mut fsm, stream_id), b"hi".to_vec());
    assert_eq!(
        fsm.take_next_event(),
        Some(super::SessionEvent::Finished(stream_id))
    );
    assert!(fsm.state.streams.contains_key(&stream_id));

    fsm.finish_stream(stream_id).unwrap();
    let fin = next_outbound(&mut fsm, now + Duration::from_millis(1)).unwrap();
    assert_eq!(
        fin.body,
        SessionBody::Stream(StreamChunk {
            stream_id,
            offset: 0,
            bytes: Vec::new(),
            fin: true,
        })
    );
    assert!(fsm.state.streams.contains_key(&stream_id));

    fsm.receive(
        now + Duration::from_millis(2),
        ack(
            2,
            SessionAck {
                base: SessionSeq(2),
                bitmap: 0,
            },
        ),
    );

    assert!(!fsm.state.streams.contains_key(&stream_id));
}

#[test]
fn replayed_remote_open_does_not_recreate_reaped_stream() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_id = ql_wire::StreamId(super::StreamNamespace::High.bit() | 17);
    let opener = SessionEnvelope {
        seq: SessionSeq(1),
        ack: SessionAck::EMPTY,
        body: SessionBody::Stream(StreamChunk {
            stream_id,
            offset: 0,
            bytes: b"hi".to_vec(),
            fin: true,
        }),
    };

    fsm.receive(now, opener.clone());

    assert_eq!(
        fsm.take_next_event(),
        Some(super::SessionEvent::Opened(stream_id))
    );
    assert_eq!(
        fsm.take_next_event(),
        Some(super::SessionEvent::Readable(stream_id))
    );
    assert_eq!(read_stream_all(&mut fsm, stream_id), b"hi".to_vec());
    assert_eq!(
        fsm.take_next_event(),
        Some(super::SessionEvent::Finished(stream_id))
    );

    fsm.finish_stream(stream_id).unwrap();
    let fin = next_outbound(&mut fsm, now + Duration::from_millis(1)).unwrap();
    assert_eq!(
        fin.body,
        SessionBody::Stream(StreamChunk {
            stream_id,
            offset: 0,
            bytes: Vec::new(),
            fin: true,
        })
    );

    fsm.receive(
        now + Duration::from_millis(2),
        ack(
            2,
            SessionAck {
                base: SessionSeq(1),
                bitmap: 0,
            },
        ),
    );

    assert!(!fsm.state.streams.contains_key(&stream_id));

    fsm.receive(now + Duration::from_millis(3), opener);

    assert_eq!(fsm.state.session_state, SessionState::Open);
    assert!(!fsm.state.streams.contains_key(&stream_id));
    assert!(fsm.take_next_event().is_none());
}

#[test]
fn duplicate_committed_data_is_not_redelivered() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_id = ql_wire::StreamId(super::StreamNamespace::High.bit() | 9);
    let body = SessionBody::Stream(StreamChunk {
        stream_id,
        offset: 0,
        bytes: b"dup".to_vec(),
        fin: false,
    });

    fsm.receive(
        now,
        SessionEnvelope {
            seq: SessionSeq(1),
            ack: SessionAck::EMPTY,
            body: body.clone(),
        },
    );
    let _ = fsm.take_next_event();
    let _ = fsm.take_next_event();
    let _ = read_stream_all(&mut fsm, stream_id);

    fsm.receive(
        now + Duration::from_millis(1),
        SessionEnvelope {
            seq: SessionSeq(2),
            ack: SessionAck::EMPTY,
            body,
        },
    );

    assert!(fsm.take_next_event().is_none());
    assert_eq!(read_stream_all(&mut fsm, stream_id), Vec::<u8>::new());
}

#[test]
fn next_outbound_round_robins_across_ready_streams() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(
        SessionFsmConfig {
            stream_chunk_size: 3,
            ..SessionFsmConfig::default()
        },
        now,
    );
    let stream_id_a = fsm.open_stream().unwrap();
    let stream_id_b = fsm.open_stream().unwrap();

    fsm.write_stream(stream_id_a, b"a-1".to_vec()).unwrap();
    fsm.write_stream(stream_id_b, b"b-1".to_vec()).unwrap();
    fsm.write_stream(stream_id_a, b"a-2".to_vec()).unwrap();
    fsm.write_stream(stream_id_b, b"b-2".to_vec()).unwrap();

    let first_round: Vec<_> = (0..2)
        .map(|_| match next_outbound(&mut fsm, now).unwrap().body {
            SessionBody::Stream(frame) => frame.stream_id,
            other => panic!("expected stream frame, got {other:?}"),
        })
        .collect();

    fsm.receive(
        now + Duration::from_millis(1),
        ack(
            1,
            SessionAck {
                base: SessionSeq(2),
                bitmap: 0,
            },
        ),
    );

    let second_round: Vec<_> = (0..2)
        .map(|_| {
            match next_outbound(&mut fsm, now + Duration::from_millis(2))
                .unwrap()
                .body
            {
                SessionBody::Stream(frame) => frame.stream_id,
                other => panic!("expected stream frame, got {other:?}"),
            }
        })
        .collect();

    assert_eq!(first_round, vec![stream_id_a, stream_id_b]);
    assert_eq!(second_round, vec![stream_id_a, stream_id_b]);
}

#[test]
fn idle_session_sends_ping_after_keepalive_interval() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(
        SessionFsmConfig {
            keepalive_interval: Duration::from_millis(50),
            ..SessionFsmConfig::default()
        },
        now,
    );

    assert_eq!(fsm.next_deadline(), Some(now + Duration::from_millis(50)));
    assert!(next_outbound(&mut fsm, now + Duration::from_millis(49)).is_none());
    fsm.on_timer(now + Duration::from_millis(50));

    let envelope = next_outbound(&mut fsm, now + Duration::from_millis(50)).unwrap();
    assert!(matches!(envelope.body, SessionBody::Ping(PingBody)));
}

#[test]
fn receive_ping_schedules_ack_without_ping_pong() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);

    fsm.receive(now, ping(1, SessionAck::EMPTY));

    let ack_envelope = next_outbound(&mut fsm, now + Duration::from_millis(10)).unwrap();
    assert_eq!(ack_envelope.body, SessionBody::Ack);

    fsm.receive(now + Duration::from_millis(20), ack(2, SessionAck::EMPTY));
    assert!(next_outbound(&mut fsm, now + Duration::from_millis(30)).is_none());
}

#[test]
fn tx_selective_ack_keeps_front_gap_pinned() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_ids: Vec<_> = (0..64).map(|_| fsm.open_stream().unwrap()).collect();

    for (byte, stream_id) in (0..64u8).zip(stream_ids.iter().copied()) {
        fsm.write_stream(stream_id, vec![byte]).unwrap();
        let _ = next_outbound(&mut fsm, now + Duration::from_millis(byte as u64))
            .unwrap();
    }

    fsm.receive(
        now + Duration::from_millis(100),
        ack(
            1,
            SessionAck {
                base: SessionSeq(0),
                bitmap: u64::MAX ^ 1,
            },
        ),
    );

    assert!(fsm.state.tx_ring.contains_key(&SessionSeq(1)));
    assert!(!fsm.state.tx_ring.contains_key(&SessionSeq(2)));

    let extra_stream = fsm.open_stream().unwrap();
    fsm.write_stream(extra_stream, b"x".to_vec()).unwrap();
    assert!(next_outbound(&mut fsm, now + Duration::from_millis(101)).is_none());

    fsm.receive(
        now + Duration::from_millis(102),
        ack(
            2,
            SessionAck {
                base: SessionSeq(1),
                bitmap: 0,
            },
        ),
    );

    assert_eq!(
        next_outbound(&mut fsm, now + Duration::from_millis(103))
            .unwrap()
            .seq,
        SessionSeq(65)
    );
}

#[test]
fn rx_seq_past_window_closes_protocol() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);

    fsm.receive(now, ping(65, SessionAck::EMPTY));

    assert_eq!(fsm.state.session_state, SessionState::Closed);
    assert!(matches!(
        fsm.take_next_event(),
        Some(super::SessionEvent::SessionClosed(close)) if close.code == CloseCode::PROTOCOL
    ));
}

#[test]
fn duplicate_old_packet_seq_is_ignored() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_id = ql_wire::StreamId(super::StreamNamespace::High.bit() | 11);
    let body = SessionBody::Stream(StreamChunk {
        stream_id,
        offset: 0,
        bytes: b"x".to_vec(),
        fin: false,
    });

    fsm.receive(
        now,
        SessionEnvelope {
            seq: SessionSeq(1),
            ack: SessionAck::EMPTY,
            body: body.clone(),
        },
    );
    let _ = fsm.take_next_event();
    let _ = fsm.take_next_event();
    let _ = read_stream_all(&mut fsm, stream_id);

    fsm.receive(
        now + Duration::from_millis(1),
        SessionEnvelope {
            seq: SessionSeq(1),
            ack: SessionAck::EMPTY,
            body,
        },
    );

    assert!(fsm.take_next_event().is_none());
    assert_eq!(read_stream_all(&mut fsm, stream_id), Vec::<u8>::new());
}

#[test]
fn retransmitted_stream_close_is_idempotent() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default(), now);
    let stream_id = fsm.open_stream().unwrap();
    let frame = StreamClose {
        stream_id,
        target: CloseTarget::Response,
        code: CloseCode::CANCELLED,
        payload: Vec::new(),
    };

    fsm.receive(
        now,
        SessionEnvelope {
            seq: SessionSeq(1),
            ack: SessionAck::EMPTY,
            body: SessionBody::StreamClose(frame.clone()),
        },
    );

    assert_eq!(
        fsm.take_next_event(),
        Some(super::SessionEvent::Closed(frame.clone()))
    );
    assert_eq!(read_stream_all(&mut fsm, stream_id), Vec::<u8>::new());

    fsm.receive(
        now + Duration::from_millis(1),
        SessionEnvelope {
            seq: SessionSeq(2),
            ack: SessionAck::EMPTY,
            body: SessionBody::StreamClose(frame),
        },
    );

    assert!(fsm.take_next_event().is_none());
    assert_eq!(read_stream_all(&mut fsm, stream_id), Vec::<u8>::new());
}
