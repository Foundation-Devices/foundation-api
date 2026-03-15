use crate::{
    runtime::{OpenedStreamDelivery, StreamConfig},
    wire::stream::{CloseCode, Direction},
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
    PollStream {
        stream_id: StreamId,
    },
    CloseOutbound {
        stream_id: StreamId,
        dir: Direction,
        code: CloseCode,
        payload: Vec<u8>,
    },
    CloseInbound {
        stream_id: StreamId,
        dir: Direction,
        code: CloseCode,
        payload: Vec<u8>,
    },
    Incoming(Vec<u8>),
}
