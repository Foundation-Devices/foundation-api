use std::{collections::VecDeque, time::Instant};

use ql_wire::{Confirm, Hello, HelloReply, QlRecord, Ready, ResponderSecrets, SessionKey};

use crate::{replay_cache::ReplayCache, FsmTime, Peer, PeerStatus, QlFsmEvent, QlSessionEvent};

#[derive(Debug, Clone)]
pub enum HandshakeInitiator {
    WaitingHelloReply {
        initiator_secret: SessionKey,
        retry_count: u8,
        retry_at: Option<Instant>,
    },
    WaitingReady {
        reply: HelloReply,
        confirm: Confirm,
        session_key: SessionKey,
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
    pub ready: Ready<Vec<u8>>,
    pub expires_at: Instant,
}

#[derive(Debug, Clone)]
pub enum ConnectionState {
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
        session_key: SessionKey,
        recent_ready: Option<RecentReady>,
    },
}

impl ConnectionState {
    pub fn status(&self) -> PeerStatus {
        match self {
            Self::Disconnected => PeerStatus::Disconnected,
            Self::Initiator { .. } => PeerStatus::Initiator,
            Self::Responder { .. } => PeerStatus::Responder,
            Self::Connected { .. } => PeerStatus::Connected,
        }
    }

    pub fn session_key(&self) -> Option<&SessionKey> {
        match self {
            Self::Connected { session_key, .. } => Some(session_key),
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
    pub outbound: VecDeque<QlRecord>,
    pub events: VecDeque<QlFsmEvent>,
    pub session_events: VecDeque<QlSessionEvent>,
    pub now: FsmTime,
}
