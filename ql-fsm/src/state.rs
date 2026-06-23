use std::time::Instant;

use ql_wire::{
    ConnectionId, EphemeralPublicKey, HandshakeId, HandshakeMeta, IkHandshake, KkHandshake,
    PairingToken, PeerBundle, QlHandshakeRecord, SessionKey, TransportParams, XxHandshake,
};

use crate::{session::SessionFsm, NoSessionError, PeerStatus};

pub struct QlFsmState {
    pub next_control_id: u32,
    pub peer: Option<PeerBundle>,
    pub armed_pairing_token: Option<PairingToken>,
    pub handshake: Option<QlHandshakeRecord>,
    pub link: LinkState,
    pub now: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTransport {
    pub tx_key: SessionKey,
    pub rx_key: SessionKey,
    pub tx_connection_id: ConnectionId,
    pub rx_connection_id: ConnectionId,
    pub remote_transport_params: TransportParams,
}

#[allow(clippy::large_enum_variant)]
pub enum LinkState {
    Idle,
    IkInitiator(InitiatorState<IkHandshake>),
    KkInitiator(InitiatorState<KkHandshake>),
    XxInitiator(InitiatorState<XxHandshake>),
    XxResponder(XxResponderState),
    Connected(ConnectedState),
}

pub struct ConnectedState {
    pub handshake_id: HandshakeId,
    pub transport: SessionTransport,
    pub session: SessionFsm,
}

#[derive(Debug, Clone)]
pub struct InitiatorState<H> {
    pub handshake: H,
    pub handshake_id: HandshakeId,
    pub deadline: Instant,
    pub initial_ephemeral: EphemeralPublicKey,
}

#[derive(Debug, Clone)]
pub struct XxResponderState {
    pub handshake: XxHandshake,
    pub handshake_meta: HandshakeMeta,
    pub deadline: Instant,
}

impl LinkState {
    pub fn take(&mut self) -> Self {
        std::mem::replace(self, Self::Idle)
    }

    pub fn status(&self) -> PeerStatus {
        match self {
            Self::Idle | Self::XxResponder(_) => PeerStatus::Disconnected,
            Self::IkInitiator(_) | Self::KkInitiator(_) | Self::XxInitiator(_) => {
                PeerStatus::Initiator
            }
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
            Self::XxInitiator(state) => Some(state.deadline),
            Self::XxResponder(state) => Some(state.deadline),
        }
    }

    #[cfg(test)]
    pub fn transport(&self) -> Option<&SessionTransport> {
        self.connected().map(|state| &state.transport)
    }
}
