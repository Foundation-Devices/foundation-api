use ql_fsm::NoSessionError;
use ql_wire::{CloseTarget, PairingToken, PeerBundle, RouteId, StreamCloseCode, StreamId};

use crate::{chunk_slot::ChunkSlotRx, QlStreamError, StreamReader};

pub enum RuntimeCommand {
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
        start: oneshot::Sender<Result<(StreamId, StreamReader), NoSessionError>>,
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
}

impl RuntimeCommand {
    #[cfg(feature = "log")]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::BindPeer { .. } => "BindPeer",
            Self::Connect => "Connect",
            Self::ArmPairing { .. } => "ArmPairing",
            Self::DisarmPairing => "DisarmPairing",
            Self::StartPairing { .. } => "StartPairing",
            Self::OpenStream { .. } => "OpenStream",
            Self::PollInbound { .. } => "PollInbound",
            Self::PollStream { .. } => "PollStream",
            Self::CloseStream { .. } => "CloseStream",
        }
    }
}
