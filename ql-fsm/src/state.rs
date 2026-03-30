use std::{collections::VecDeque, time::Instant};

use ql_wire::{
    ConnectionId, EphemeralPublicKey, KkHandshake, PeerBundle, QlHandshakeRecord, SessionKey,
    XxHandshake,
};

use crate::{replay_cache::ReplayCache, FsmTime, PeerStatus, QlFsmEvent, QlSessionEvent};

pub struct QlFsmState {
    pub replay_cache: ReplayCache,
    pub next_control_id: u32,
    pub peer: Option<PeerBundle>,
    pub handshake: Option<QlHandshakeRecord>,
    pub link: LinkState,
    pub events: VecDeque<QlFsmEvent>,
    pub session_events: VecDeque<QlSessionEvent>,
    pub now: FsmTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTransport {
    pub tx_key: SessionKey,
    pub rx_key: SessionKey,
    pub tx_connection_id: ConnectionId,
    pub rx_connection_id: ConnectionId,
}

impl SessionTransport {
    pub fn from_finalized(finalized: ql_wire::FinalizedHandshake) -> (Self, PeerBundle) {
        (
            Self {
                tx_key: finalized.tx_key,
                rx_key: finalized.rx_key,
                tx_connection_id: finalized.tx_connection_id,
                rx_connection_id: finalized.rx_connection_id,
            },
            finalized.remote_bundle,
        )
    }
}

#[derive(Debug, Clone)]
pub enum LinkState {
    Idle,
    XxInitiator {
        handshake: XxHandshake,
        deadline: Instant,
        initial_ephemeral: EphemeralPublicKey,
    },
    XxResponder {
        handshake: XxHandshake,
        deadline: Instant,
    },
    KkInitiator {
        handshake: KkHandshake,
        deadline: Instant,
        initial_ephemeral: EphemeralPublicKey,
    },
    Connected(SessionTransport),
}

impl LinkState {
    pub fn status(&self) -> PeerStatus {
        match self {
            Self::Idle => PeerStatus::Disconnected,
            Self::XxInitiator { .. } | Self::KkInitiator { .. } => PeerStatus::Initiator,
            Self::XxResponder { .. } => PeerStatus::Responder,
            Self::Connected(_) => PeerStatus::Connected,
        }
    }

    pub fn transport(&self) -> Option<&SessionTransport> {
        match self {
            Self::Connected(transport) => Some(transport),
            _ => None,
        }
    }

    pub fn handshake_deadline(&self) -> Option<Instant> {
        match self {
            Self::Idle | Self::Connected(_) => None,
            Self::XxInitiator { deadline, .. }
            | Self::XxResponder { deadline, .. }
            | Self::KkInitiator { deadline, .. } => Some(*deadline),
        }
    }
}

impl QlFsmState {
    pub fn ensure_peer_bound(&self) -> Result<(), crate::QlFsmError> {
        self.peer
            .as_ref()
            .map(|_| ())
            .ok_or(crate::QlFsmError::NoPeerBound)
    }
}
