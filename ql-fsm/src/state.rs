use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use bc_components::{MLDSAPublicKey, MLKEMPublicKey, SymmetricKey};
use ql_wire::{
    handshake::{Confirm, Hello, HelloReply, Ready, ResponderSecrets},
    QlIdentity, QlRecord, WireError, XID,
};
use thiserror::Error;

use crate::{replay_cache::ReplayCache, FsmTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub xid: XID,
    pub signing_key: MLDSAPublicKey,
    pub encapsulation_key: MLKEMPublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStatus {
    Disconnected,
    Initiator,
    Responder,
    Connected,
}

#[derive(Debug, Clone)]
pub enum QlFsmEvent {
    PersistPeer(Peer),
    ClearPeer,
    PeerStatusChanged { peer: XID, status: PeerStatus },
}

#[derive(Debug, Clone, Copy)]
pub struct QlFsmConfig {
    pub handshake_timeout: Duration,
    pub handshake_retry_interval: Duration,
    pub max_handshake_retries: u8,
    pub control_expiration: Duration,
}

impl Default for QlFsmConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
            handshake_retry_interval: Duration::from_millis(750),
            max_handshake_retries: 3,
            control_expiration: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone)]
pub enum HandshakeInitiator {
    WaitingHelloReply {
        initiator_secret: SymmetricKey,
        retry_count: u8,
        retry_at: Option<Instant>,
    },
    WaitingReady {
        reply: HelloReply,
        confirm: Confirm,
        session_key: SymmetricKey,
        retry_count: u8,
        retry_at: Option<Instant>,
    },
}

#[derive(Debug, Clone)]
pub enum HandshakeResponder {
    WaitingConfirm {
        secrets: ResponderSecrets,
        retry_count: u8,
        retry_at: Option<Instant>,
    },
}

#[derive(Debug, Clone)]
pub struct RecentReady {
    pub hello: Hello,
    pub reply: HelloReply,
    pub ready: Ready,
    pub expires_at: Instant,
}

#[derive(Debug, Clone)]
pub enum PeerSession {
    Disconnected,
    Initiator {
        hello: Hello,
        deadline: Instant,
        stage: HandshakeInitiator,
    },
    Responder {
        hello: Hello,
        reply: HelloReply,
        deadline: Instant,
        stage: HandshakeResponder,
    },
    Connected {
        session_key: SymmetricKey,
        recent_ready: Option<RecentReady>,
    },
}

impl PeerSession {
    pub fn status(&self) -> PeerStatus {
        match self {
            Self::Disconnected => PeerStatus::Disconnected,
            Self::Initiator { .. } => PeerStatus::Initiator,
            Self::Responder { .. } => PeerStatus::Responder,
            Self::Connected { .. } => PeerStatus::Connected,
        }
    }

    pub fn session_key(&self) -> Option<&SymmetricKey> {
        match self {
            Self::Connected { session_key, .. } => Some(session_key),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub peer: Peer,
    pub session: PeerSession,
}

impl PeerRecord {
    pub fn new(peer: Peer) -> Self {
        Self {
            peer,
            session: PeerSession::Disconnected,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum QlFsmError {
    #[error("invalid payload")]
    InvalidPayload,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("expired")]
    Expired,
    #[error("no peer bound")]
    NoPeerBound,
}

impl From<WireError> for QlFsmError {
    fn from(value: WireError) -> Self {
        match value {
            WireError::InvalidPayload => Self::InvalidPayload,
            WireError::InvalidSignature => Self::InvalidSignature,
            WireError::Expired => Self::Expired,
        }
    }
}

pub struct QlFsm {
    pub config: QlFsmConfig,
    pub identity: QlIdentity,
    pub peer: Option<PeerRecord>,
    pub state: QlFsmState,
}

pub struct QlFsmState {
    pub replay_cache: ReplayCache,
    pub next_control_id: u32,
    pub outbound: VecDeque<QlRecord>,
    pub events: VecDeque<QlFsmEvent>,
    pub now: FsmTime,
}
