use ql_fsm::{NoSessionError, PairingInvite};
use ql_wire::{
    CloseTarget, PairingToken, PeerBundle, RouteId, ServiceId, SessionCloseCode, StreamCloseCode,
    StreamId,
};

use crate::{StreamReader, StreamWriter};

pub enum Command {
    BindPeer {
        peer: PeerBundle,
    },
    Connect,
    ArmPairing {
        token: PairingToken,
    },
    DisarmPairing,
    StartPairing {
        invite: PairingInvite,
    },
    OpenStream {
        service_id: ServiceId,
        route_id: RouteId,
        start: oneshot::Sender<Result<(StreamId, StreamReader, StreamWriter), NoSessionError>>,
    },
    PollInbound {
        stream_id: StreamId,
    },
    PollStream {
        stream_id: StreamId,
    },
    CloseSession {
        code: SessionCloseCode,
    },
    Unpair,
    CloseStream {
        stream_id: StreamId,
        target: CloseTarget,
        code: StreamCloseCode,
    },
}

impl Command {
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
            Self::CloseSession { .. } => "CloseSession",
            Self::Unpair => "Unpair",
            Self::CloseStream { .. } => "CloseStream",
        }
    }
}
