use ql_wire::{CloseTarget, PeerBundle, StreamCloseCode, StreamId};

use crate::{chunk_slot::ChunkSlotRx, ByteReader, QlError, QlStreamError};

pub(crate) enum RuntimeCommand {
    BindPeer {
        peer: PeerBundle,
    },
    Connect,
    OpenStream {
        request_reader: ChunkSlotRx,
        request_terminal: oneshot::Sender<QlStreamError>,
        start: oneshot::Sender<Result<(StreamId, ByteReader), QlError>>,
    },
    PollInbound {
        stream_id: StreamId,
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
