use std::time::Instant;

use ql_wire::{
    ConnectionId, EphemeralPublicKey, HandshakeId, IkHandshake, KkHandshake, PeerBundle,
    QlHandshakeRecord, SessionKey, TransportParams,
};

use crate::{replay_cache::ReplayCache, session::SessionFsm, FsmTime, NoSessionError, PeerStatus};

pub struct QlFsmState {
    pub replay_cache: ReplayCache,
    pub next_control_id: u32,
    pub peer: Option<PeerBundle>,
    pub handshake: Option<QlHandshakeRecord>,
    pub link: LinkState,
    pub now: FsmTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTransport {
    pub tx_key: SessionKey,
    pub rx_key: SessionKey,
    pub tx_connection_id: ConnectionId,
    pub rx_connection_id: ConnectionId,
    pub remote_transport_params: TransportParams,
}

impl SessionTransport {
    pub fn from_finalized(finalized: ql_wire::FinalizedHandshake) -> (Self, PeerBundle) {
        (
            Self {
                tx_key: finalized.tx_key,
                rx_key: finalized.rx_key,
                tx_connection_id: finalized.tx_connection_id,
                rx_connection_id: finalized.rx_connection_id,
                remote_transport_params: finalized.remote_transport_params,
            },
            finalized.remote_bundle,
        )
    }
}

pub enum LinkState {
    Idle,
    IkInitiator(IkInitiatorState),
    KkInitiator(KkInitiatorState),
    Connected(ConnectedState),
}

pub struct ConnectedState {
    pub transport: SessionTransport,
    pub session: SessionFsm,
}

#[derive(Debug, Clone)]
pub struct IkInitiatorState {
    pub handshake: IkHandshake,
    pub handshake_id: HandshakeId,
    pub deadline: Instant,
    pub initial_ephemeral: EphemeralPublicKey,
}

#[derive(Debug, Clone)]
pub struct KkInitiatorState {
    pub handshake: KkHandshake,
    pub handshake_id: HandshakeId,
    pub deadline: Instant,
    pub initial_ephemeral: EphemeralPublicKey,
}

impl LinkState {
    pub fn take(&mut self) -> Self {
        std::mem::replace(self, Self::Idle)
    }

    pub fn status(&self) -> PeerStatus {
        match self {
            Self::Idle => PeerStatus::Disconnected,
            Self::IkInitiator(_) | Self::KkInitiator(_) => PeerStatus::Initiator,
            Self::Connected(_) => PeerStatus::Connected,
        }
    }

    #[inline]
    pub fn connected(&self) -> Option<&ConnectedState> {
        match self {
            Self::Connected(state) => Some(state),
            _ => None,
        }
    }

    #[inline]
    pub fn connected_mut(&mut self) -> Option<&mut ConnectedState> {
        match self {
            Self::Connected(state) => Some(state),
            _ => None,
        }
    }

    #[inline]
    pub fn connected_mut_or_err(&mut self) -> Result<&mut ConnectedState, NoSessionError> {
        self.connected_mut().ok_or(NoSessionError)
    }

    pub fn handshake_deadline(&self) -> Option<Instant> {
        match self {
            Self::Idle | Self::Connected(_) => None,
            Self::IkInitiator(state) => Some(state.deadline),
            Self::KkInitiator(state) => Some(state.deadline),
        }
    }

    #[cfg(test)]
    pub fn transport(&self) -> Option<&SessionTransport> {
        self.connected().map(|state| &state.transport)
    }
}
