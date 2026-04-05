use crate::{
    wire::{CloseTarget, StreamCloseCode},
    OpenedStreamDelivery, PeerBundle, QlError, StreamId,
};

pub(crate) enum RuntimeCommand {
    BindPeer {
        peer: PeerBundle,
    },
    Connect,
    OpenStream {
        request_reader: piper::Reader,
        start: oneshot::Sender<Result<OpenedStreamDelivery, QlError>>,
    },
    PollStream {
        stream_id: StreamId,
    },
    CloseStream {
        stream_id: StreamId,
        target: CloseTarget,
        code: StreamCloseCode,
    },
    Incoming(Vec<u8>),
}
