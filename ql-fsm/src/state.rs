use std::{collections::VecDeque, time::Instant};

use ql_wire::{
    ConnectionId, EphemeralPublicKey, HandshakeId, KkHandshake, PeerBundle, QlHandshakeRecord,
    SessionKey, XxHandshake,
};

use crate::{replay_cache::ReplayCache, FsmTime, Peer, PeerStatus, QlFsmEvent, QlSessionEvent};

#[derive(Debug, Clone)]
pub enum HandshakeMode {
    XxInitiator(XxHandshake),
    XxResponder(XxHandshake),
    KkInitiator(KkHandshake),
}

#[derive(Debug, Clone)]
pub struct HandshakeState {
    pub id: HandshakeId,
    pub deadline: Instant,
    pub mode: HandshakeMode,
    pub initial_ephemeral: Option<EphemeralPublicKey>,
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
pub enum ConnectionState {
    Disconnected,
    Handshaking(HandshakeState),
    Connected(SessionTransport),
}

impl ConnectionState {
    pub fn status(&self) -> PeerStatus {
        match self {
            Self::Disconnected => PeerStatus::Disconnected,
            Self::Handshaking(HandshakeState { mode, .. }) => match mode {
                HandshakeMode::XxInitiator(_) | HandshakeMode::KkInitiator(_) => {
                    PeerStatus::Initiator
                }
                HandshakeMode::XxResponder(_) => PeerStatus::Responder,
            },
            Self::Connected(_) => PeerStatus::Connected,
        }
    }

    pub fn transport(&self) -> Option<&SessionTransport> {
        match self {
            Self::Connected(transport) => Some(transport),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub peer: Peer,
    pub session: ConnectionState,
}

impl PeerRecord {
    pub fn new(peer: Peer) -> Self {
        Self {
            peer,
            session: ConnectionState::Disconnected,
        }
    }
}

pub struct QlFsmState {
    pub replay_cache: ReplayCache,
    pub next_control_id: u32,
    pub handshake: Option<QlHandshakeRecord>,
    pub events: VecDeque<QlFsmEvent>,
    pub session_events: VecDeque<QlSessionEvent>,
    pub now: FsmTime,
}
