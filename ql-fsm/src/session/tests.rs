use std::time::{Duration, Instant};

use ql_wire::{
    encrypted::heartbeat::HeartbeatBody, CloseCode, CloseTarget, SessionAck, SessionBody,
    SessionEnvelope, SessionSeq, StreamFrame,
};

use super::{SessionFsm, SessionFsmConfig, SessionState};

fn heartbeat(seq: u64, ack: SessionAck) -> SessionEnvelope {
    SessionEnvelope {
        seq: SessionSeq(seq),
        ack,
        body: SessionBody::Heartbeat(HeartbeatBody),
    }
}

#[test]
fn outbound_session_seq_increments_monotonically() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default());
    let stream_id = fsm.open_stream().unwrap();

    fsm.write_stream(stream_id, b"one".to_vec()).unwrap();
    let first = fsm.next_outbound(now).unwrap();

    fsm.write_stream(stream_id, b"two".to_vec()).unwrap();
    let second = fsm.next_outbound(now + Duration::from_millis(1)).unwrap();

    assert_eq!(first.seq, SessionSeq(1));
    assert_eq!(second.seq, SessionSeq(2));
}

#[test]
fn inbound_ack_removes_acked_tx_entries() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default());
    let stream_id = fsm.open_stream().unwrap();

    fsm.write_stream(stream_id, b"one".to_vec()).unwrap();
    let first = fsm.next_outbound(now).unwrap();
    assert_eq!(first.seq, SessionSeq(1));
    assert!(fsm.state.tx_ring.contains_key(&SessionSeq(1)));

    fsm.receive(
        now + Duration::from_millis(1),
        heartbeat(
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
    let mut fsm = SessionFsm::new(SessionFsmConfig::default());

    fsm.receive(now, heartbeat(2, SessionAck::EMPTY));
    let gap_ack = fsm.next_outbound(now).unwrap();
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
        heartbeat(1, SessionAck::EMPTY),
    );
    let contiguous_ack = fsm.next_outbound(now + Duration::from_millis(10)).unwrap();
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
fn retransmit_requeues_body_with_new_session_seq() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default());
    let stream_id = fsm.open_stream().unwrap();

    fsm.write_stream(stream_id, b"retry-me".to_vec()).unwrap();
    let first = fsm.next_outbound(now).unwrap();

    let retransmit_at = now + Duration::from_millis(200);
    let retried = fsm.next_outbound(retransmit_at).unwrap();

    assert_eq!(first.seq, SessionSeq(1));
    assert_eq!(retried.seq, SessionSeq(2));
    assert_eq!(retried.body, first.body);
}

#[test]
fn repeated_outbound_messages_keep_reporting_latest_receive_ack() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default());
    let stream_id = fsm.open_stream().unwrap();

    fsm.receive(now, heartbeat(1, SessionAck::EMPTY));

    fsm.write_stream(stream_id, b"one".to_vec()).unwrap();
    let first = fsm.next_outbound(now).unwrap();

    fsm.write_stream(stream_id, b"two".to_vec()).unwrap();
    let second = fsm.next_outbound(now + Duration::from_millis(1)).unwrap();

    assert_eq!(first.ack.base, SessionSeq(1));
    assert_eq!(second.ack.base, SessionSeq(1));
    assert_eq!(first.ack.bitmap, 0);
    assert_eq!(second.ack.bitmap, 0);
}

#[test]
fn local_inbound_close_ignores_late_remote_bytes() {
    let now = Instant::now();
    let mut fsm = SessionFsm::new(SessionFsmConfig::default());
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
            body: SessionBody::Stream(StreamFrame {
                stream_id,
                offset: 0,
                bytes: b"late".to_vec(),
                fin: false,
            }),
        },
    );

    assert_eq!(fsm.session_state(), SessionState::Open);
    assert!(fsm.take_next_inbound(stream_id).is_none());
    assert!(fsm.take_next_event().is_none());
}
