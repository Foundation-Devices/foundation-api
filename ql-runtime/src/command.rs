use ql_common::{ResetCode, StreamId};
use ql_fsm::{NoSessionError, PairingInvite, StreamOptions, StreamResetTarget};
use ql_wire::{PairingToken, PeerBundle, SessionCloseCode};

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
        header: Box<[u8]>,
        options: StreamOptions,
        start: oneshot::Sender<Result<(StreamReader, StreamWriter), NoSessionError>>,
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
    ResetStream {
        stream_id: StreamId,
        target: StreamResetTarget,
        code: ResetCode,
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
            Self::ResetStream { .. } => "ResetStream",
        }
    }
}
