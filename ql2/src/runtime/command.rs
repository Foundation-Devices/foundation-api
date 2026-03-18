use crate::{
    runtime::{pipe, AcceptedStreamDelivery, StreamConfig},
    wire::stream::{Direction, RejectCode, ResetCode},
    Peer, QlError, StreamId,
};

pub(crate) enum RuntimeCommand {
    BindPeer {
        peer: Peer,
    },
    Pair,
    Connect,
    Unpair,
    OpenStream {
        request_head: Vec<u8>,
        request_pipe: pipe::PipeReader<QlError>,
        accepted: oneshot::Sender<Result<AcceptedStreamDelivery, QlError>>,
        start: oneshot::Sender<Result<StreamId, QlError>>,
        config: StreamConfig,
    },
    AcceptStream {
        stream_id: StreamId,
        response_head: Vec<u8>,
        response_pipe: pipe::PipeReader<QlError>,
    },
    RejectStream {
        stream_id: StreamId,
        code: RejectCode,
    },
    PollStream {
        stream_id: StreamId,
    },
    AdvanceInboundCredit {
        stream_id: StreamId,
        dir: Direction,
        amount: u64,
    },
    ResetOutbound {
        stream_id: StreamId,
        dir: Direction,
        code: ResetCode,
    },
    ResetInbound {
        stream_id: StreamId,
        dir: Direction,
        code: ResetCode,
    },
    ResponderDropped {
        stream_id: StreamId,
    },
    PendingAcceptDropped {
        stream_id: StreamId,
    },
    Incoming(Vec<u8>),
}
