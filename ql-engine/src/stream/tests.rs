use std::time::Instant;

use super::{
    Outbound, StreamConfig, StreamError, StreamEventSink, StreamFsm, StreamNamespace, WriteError,
};
use crate::{
    wire::stream::{
        BodyChunk, CloseCode, CloseTarget, StreamAck, StreamAckBody, StreamBody, StreamFrame,
        StreamFrameClose, StreamFrameData, StreamFrameOpen, StreamMessage,
    },
    StreamId,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct OpenedStream {
    stream_id: StreamId,
    request_head: Vec<u8>,
    request_prefix: Option<BodyChunk>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InboundChunk {
    stream_id: StreamId,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamFailure {
    stream_id: StreamId,
    error: StreamError,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Recorder {
    opened: Vec<OpenedStream>,
    closes: Vec<StreamFrameClose>,
    inbound_data: Vec<InboundChunk>,
    inbound_finished: Vec<StreamId>,
    inbound_failed: Vec<StreamFailure>,
    outbound_closed: Vec<StreamId>,
    outbound_failed: Vec<StreamFailure>,
    reaped: Vec<StreamId>,
}

impl StreamEventSink for Recorder {
    fn opened(
        &mut self,
        stream_id: StreamId,
        request_head: Vec<u8>,
        request_prefix: Option<BodyChunk>,
    ) {
        self.opened.push(OpenedStream {
            stream_id,
            request_head,
            request_prefix,
        });
    }

    fn inbound_data(&mut self, stream_id: StreamId, bytes: Vec<u8>) {
        self.inbound_data.push(InboundChunk { stream_id, bytes });
    }

    fn inbound_finished(&mut self, stream_id: StreamId) {
        self.inbound_finished.push(stream_id);
    }

    fn inbound_failed(&mut self, stream_id: StreamId, error: StreamError) {
        self.inbound_failed.push(StreamFailure { stream_id, error });
    }

    fn close(&mut self, frame: StreamFrameClose) {
        self.closes.push(frame);
    }

    fn outbound_closed(&mut self, stream_id: StreamId) {
        self.outbound_closed.push(stream_id);
    }

    fn outbound_failed(&mut self, stream_id: StreamId, error: StreamError) {
        self.outbound_failed
            .push(StreamFailure { stream_id, error });
    }

    fn reaped(&mut self, stream_id: StreamId) {
        self.reaped.push(stream_id);
    }
}

fn data_packet(stream_id: StreamId, tx_seq: u32, byte: u8) -> StreamBody {
    StreamBody::Message(StreamMessage {
        tx_seq: crate::wire::StreamSeq(tx_seq),
        ack: StreamAck::EMPTY,
        valid_until: 0,
        frame: StreamFrame::Data(StreamFrameData {
            stream_id,
            chunk: BodyChunk {
                bytes: vec![byte],
                fin: false,
            },
        }),
    })
}

#[test]
fn open_stream_enqueues_open_packet() {
    let now = Instant::now();
    let mut stream = StreamFsm::new(StreamConfig::default());
    let stream_id = stream.open_stream(b"open".to_vec(), None);

    let outbound = stream.next_outbound(now, 7).unwrap();
    assert_open(outbound, stream_id, b"open", 7);
}

#[test]
fn out_of_order_remote_stream_buffers_until_open_arrives() {
    let now = Instant::now();
    let mut stream = StreamFsm::new(StreamConfig {
        local_namespace: StreamNamespace::Low,
        ..Default::default()
    });
    let stream_id = StreamId(StreamNamespace::High.bit() | 1);

    let mut events = Recorder::default();
    stream.receive(now, data_packet(stream_id, 2, b'h'), &mut events);
    assert!(events.opened.is_empty());
    assert!(events.inbound_data.is_empty());

    stream.receive(
        now,
        StreamBody::Message(StreamMessage {
            tx_seq: crate::wire::StreamSeq::START,
            ack: StreamAck::EMPTY,
            valid_until: 0,
            frame: StreamFrame::Open(StreamFrameOpen {
                stream_id,
                request_head: b"late-open".to_vec(),
                request_prefix: None,
            }),
        }),
        &mut events,
    );

    assert_eq!(
        events.opened,
        vec![OpenedStream {
            stream_id,
            request_head: b"late-open".to_vec(),
            request_prefix: None,
        }]
    );
    assert_eq!(
        events.inbound_data,
        vec![InboundChunk {
            stream_id,
            bytes: vec![b'h'],
        }]
    );
}

#[test]
fn ack_only_write_failure_requeues_without_spending_sequence_space() {
    let now = Instant::now();
    let config = StreamConfig::default();
    let mut stream = StreamFsm::new(config);
    let stream_id = StreamId(StreamNamespace::High.bit() | 1);

    let mut events = Recorder::default();
    stream.receive(
        now,
        StreamBody::Message(StreamMessage {
            tx_seq: crate::wire::StreamSeq::START,
            ack: StreamAck::EMPTY,
            valid_until: 0,
            frame: StreamFrame::Open(StreamFrameOpen {
                stream_id,
                request_head: b"open".to_vec(),
                request_prefix: None,
            }),
        }),
        &mut events,
    );
    assert_eq!(events.opened.len(), 1);

    stream.on_timer(now + config.ack_delay, &mut ());
    let ack_write = stream.next_outbound(now + config.ack_delay, 11).unwrap();
    assert!(matches!(
        ack_write.body,
        StreamBody::Ack(StreamAckBody {
            stream_id: id,
            ack: StreamAck {
                base: crate::wire::StreamSeq::START,
                bitmap: 0,
            },
            valid_until: 11,
        }) if id == stream_id
    ));

    stream.complete_outbound(
        now + config.ack_delay,
        ack_write.completion,
        Err(WriteError::SendFailed),
        &mut (),
    );
    let retry = stream.next_outbound(now + config.ack_delay, 12).unwrap();
    assert!(matches!(retry.body, StreamBody::Ack(_)));

    stream.complete_outbound(now + config.ack_delay, retry.completion, Ok(()), &mut ());
    stream.write_stream(stream_id, b"resp".to_vec()).unwrap();
    let response = stream.next_outbound(now, 13).unwrap();
    assert!(matches!(
        response.body,
        StreamBody::Message(StreamMessage {
            tx_seq: crate::wire::StreamSeq::START,
            valid_until: 13,
            frame: StreamFrame::Data(StreamFrameData {
                stream_id: id,
                chunk: BodyChunk { bytes, fin: false },
            }),
            ..
        }) if id == stream_id && bytes == b"resp"
    ));
}

#[test]
fn fast_retransmit_resends_oldest_gap_when_threshold_met() {
    let now = Instant::now();
    let mut stream = StreamFsm::new(StreamConfig {
        fast_retransmit_threshold: 2,
        ..Default::default()
    });
    let stream_id = stream.open_stream(b"open".to_vec(), None);
    let open = stream.next_outbound(now, 1).unwrap();
    stream.complete_outbound(now, open.completion, Ok(()), &mut ());
    stream.write_stream(stream_id, b"a".to_vec()).unwrap();
    stream.write_stream(stream_id, b"b".to_vec()).unwrap();
    stream.write_stream(stream_id, b"c".to_vec()).unwrap();
    stream.write_stream(stream_id, b"d".to_vec()).unwrap();
    let first = stream.next_outbound(now, 2).unwrap();
    let second = stream.next_outbound(now, 3).unwrap();
    let third = stream.next_outbound(now, 4).unwrap();
    let fourth = stream.next_outbound(now, 5).unwrap();
    stream.complete_outbound(now, first.completion, Ok(()), &mut ());
    stream.complete_outbound(now, second.completion, Ok(()), &mut ());
    stream.complete_outbound(now, third.completion, Ok(()), &mut ());
    stream.complete_outbound(now, fourth.completion, Ok(()), &mut ());

    stream.receive(
        now,
        StreamBody::Ack(StreamAckBody {
            stream_id,
            ack: StreamAck {
                base: crate::wire::StreamSeq(2),
                bitmap: 0b0000_0110,
            },
            valid_until: 0,
        }),
        &mut (),
    );

    let retransmit = stream.next_outbound(now, 6).unwrap();
    assert!(matches!(
        retransmit.body,
        StreamBody::Message(StreamMessage {
            tx_seq: crate::wire::StreamSeq(3),
            frame: StreamFrame::Data(_),
            ..
        })
    ));
}

#[test]
fn late_failed_write_after_remote_close_ack_is_ignored() {
    let now = Instant::now();
    let mut stream = StreamFsm::new(StreamConfig::default());
    let stream_id = stream.open_stream(b"open".to_vec(), None);
    let open = stream.next_outbound(now, 1).unwrap();

    let mut events = Recorder::default();
    stream.receive(
        now,
        StreamBody::Message(StreamMessage {
            tx_seq: crate::wire::StreamSeq::START,
            ack: StreamAck {
                base: crate::wire::StreamSeq::START,
                bitmap: 0,
            },
            valid_until: 0,
            frame: StreamFrame::Close(StreamFrameClose {
                stream_id,
                target: CloseTarget::Both,
                code: CloseCode::PROTOCOL,
                payload: Vec::new(),
            }),
        }),
        &mut events,
    );
    assert_eq!(
        events.closes,
        vec![StreamFrameClose {
            stream_id,
            target: CloseTarget::Both,
            code: CloseCode::PROTOCOL,
            payload: Vec::new(),
        }]
    );
    assert!(events.outbound_failed.is_empty());
    assert!(events.inbound_failed.is_empty());

    let mut late = Recorder::default();
    stream.complete_outbound(now, open.completion, Err(WriteError::SendFailed), &mut late);
    assert!(late.outbound_failed.is_empty());
    assert!(late.inbound_failed.is_empty());
}

fn assert_open(outbound: Outbound, stream_id: StreamId, request_head: &[u8], valid_until: u64) {
    assert!(matches!(
        outbound.body,
        StreamBody::Message(StreamMessage {
            tx_seq: crate::wire::StreamSeq::START,
            ack: StreamAck::EMPTY,
            valid_until: expires_at,
            frame: StreamFrame::Open(StreamFrameOpen {
                stream_id: id,
                request_head: actual_head,
                request_prefix: None,
            }),
        }) if id == stream_id && actual_head == request_head && expires_at == valid_until
    ));
}
