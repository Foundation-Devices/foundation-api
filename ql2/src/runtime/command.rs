use crate::{
    runtime::{OpenedStreamDelivery, StreamConfig},
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
        request_reader: piper::Reader,
        start: oneshot::Sender<Result<OpenedStreamDelivery, QlError>>,
        config: StreamConfig,
    },
    AcceptStream {
        stream_id: StreamId,
        response_head: Vec<u8>,
        response_reader: piper::Reader,
    },
    RejectStream {
        stream_id: StreamId,
        code: RejectCode,
    },
    PollStream {
        stream_id: StreamId,
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
    Incoming(Vec<u8>),
}
