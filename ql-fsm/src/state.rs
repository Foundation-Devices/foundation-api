use std::time::Instant;

use ql_common::QID;
use ql_wire::{
    HandshakeId, IkHandshake, PairingToken, PeerBundle, QlHandshakeRecord, RouteHeader, SessionKey,
    TransportParams, XxHandshake,
};

use crate::{session::SessionFsm, NoSessionError, PeerStatus};

pub struct QlFsmState<M> {
    pub next_control_id: u32,
    pub peer: Option<PeerBundle>,
    pub armed_pairing_token: Option<PairingToken>,
    pub handshake: Option<(RouteHeader, QlHandshakeRecord)>,
    pub link: LinkState<M>,
    pub now: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTransport {
    pub remote_qid: QID,
    pub tx_key: SessionKey,
    pub rx_key: SessionKey,
    pub remote_transport_params: TransportParams,
}

#[allow(clippy::large_enum_variant)]
pub enum LinkState<M> {
    Idle,
    IkInitiator(InitiatorState<IkHandshake>),
    XxInitiator(InitiatorState<XxHandshake>),
    XxResponder(XxResponderState),
    Connected(ConnectedState<M>),
}

pub struct ConnectedState<M> {
    pub handshake_id: HandshakeId,
    pub transport: SessionTransport,
    pub session: SessionFsm<M>,
}

#[derive(Debug, Clone)]
pub struct InitiatorState<H> {
    pub handshake: H,
    pub deadline: Instant,
}

#[derive(Debug, Clone)]
pub struct XxResponderState {
    pub handshake: XxHandshake,
    pub deadline: Instant,
}

impl<M> LinkState<M> {
    pub fn take(&mut self) -> Self {
        std::mem::replace(self, Self::Idle)
    }

    pub fn status(&self) -> PeerStatus {
        match self {
            Self::Idle | Self::XxResponder(_) => PeerStatus::Disconnected,
            Self::IkInitiator(_) | Self::XxInitiator(_) => PeerStatus::Initiator,
            Self::Connected(_) => PeerStatus::Connected,
        }
    }

    #[inline]
    pub fn connected(&self) -> Option<&ConnectedState<M>> {
        match self {
            Self::Connected(state) => Some(state),
            _ => None,
        }
    }

    #[inline]
    pub fn connected_mut(&mut self) -> Option<&mut ConnectedState<M>> {
        match self {
            Self::Connected(state) => Some(state),
            _ => None,
        }
    }

    #[inline]
    pub fn connected_mut_or_err(&mut self) -> Result<&mut ConnectedState<M>, NoSessionError> {
        self.connected_mut().ok_or(NoSessionError)
    }

    pub fn handshake_deadline(&self) -> Option<Instant> {
        match self {
            Self::Idle | Self::Connected(_) => None,
            Self::IkInitiator(state) => Some(state.deadline),
            Self::XxInitiator(state) => Some(state.deadline),
            Self::XxResponder(state) => Some(state.deadline),
        }
    }

    #[cfg(test)]
    pub fn transport(&self) -> Option<&SessionTransport> {
        self.connected().map(|state| &state.transport)
    }
}
