use ql_fsm::NoSessionError;
use ql_wire::{CloseTarget, PairingToken, PeerBundle, RouteId, StreamCloseCode, StreamId};

use crate::{chunk_slot::ChunkSlotRx, ByteReader, QlStreamError};

pub(crate) enum RuntimeCommand {
    BindPeer {
        peer: PeerBundle,
    },
    Connect,
    ArmPairing {
        token: PairingToken,
    },
    DisarmPairing,
    StartPairing {
        token: PairingToken,
    },
    OpenStream {
        route_id: RouteId,
        request_reader: ChunkSlotRx,
        request_terminal: oneshot::Sender<Result<(), QlStreamError>>,
        start: oneshot::Sender<Result<(StreamId, ByteReader), NoSessionError>>,
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
    Receive(Vec<u8>),
}
