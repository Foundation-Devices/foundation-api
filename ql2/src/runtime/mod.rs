use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use bc_components::{EncapsulationPublicKey, SigningPublicKey, SymmetricKey, XID};
use dcbor::CBOR;
use oneshot::Receiver;

use crate::{
    crypto::handshake::ResponderSecrets,
    wire::{handshake::Hello, handshake::HelloReply, record::RecordKind},
    MessageId, QlError, RouteId,
};

#[derive(Debug, Clone, Default)]
pub struct RequestConfig {
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeConfig {
    pub handshake_timeout: Duration,
    pub default_request_timeout: Duration,
    pub message_expiration: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token(u64);

impl Token {
    fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

impl RuntimeConfig {
    pub fn new(handshake_timeout: Duration) -> Self {
        Self {
            handshake_timeout,
            default_request_timeout: Duration::from_secs(5),
            message_expiration: Duration::from_secs(30),
        }
    }

    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.default_request_timeout = timeout;
        self
    }

    pub fn with_message_expiration(mut self, expiration: Duration) -> Self {
        self.message_expiration = expiration;
        self
    }
}

#[derive(Clone)]
pub struct RuntimeHandle {
    tx: async_channel::Sender<RuntimeCommand>,
    next_message_id: Arc<AtomicU64>,
}

pub struct RequestTicket {
    pub id: MessageId,
    rx: Receiver<Result<CBOR, QlError>>,
}

impl RequestTicket {
    pub async fn recv(self) -> Result<CBOR, QlError> {
        self.rx.await.unwrap_or(Err(QlError::Cancelled))
    }
}

impl RuntimeHandle {
    fn next_message_id(&self) -> MessageId {
        let value = self.next_message_id.fetch_add(1, Ordering::Relaxed);
        MessageId::new(value)
    }

    pub async fn register_peer(
        &self,
        peer: XID,
        signing_key: SigningPublicKey,
        encapsulation_key: EncapsulationPublicKey,
    ) -> Result<(), async_channel::SendError<RuntimeCommand>> {
        self.tx
            .send(RuntimeCommand::RegisterPeer {
                peer,
                signing_key,
                encapsulation_key,
            })
            .await
    }

    pub async fn connect(
        &self,
        peer: XID,
    ) -> Result<(), async_channel::SendError<RuntimeCommand>> {
        self.tx.send(RuntimeCommand::Connect { peer }).await
    }

    pub async fn send_incoming(
        &self,
        bytes: Vec<u8>,
    ) -> Result<(), async_channel::SendError<RuntimeCommand>> {
        self.tx.send(RuntimeCommand::Incoming(bytes)).await
    }

    pub async fn send_request(
        &self,
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
        config: RequestConfig,
    ) -> Result<RequestTicket, async_channel::SendError<RuntimeCommand>> {
        let id = self.next_message_id();
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(RuntimeCommand::SendRequest {
                id,
                recipient,
                route_id,
                payload,
                respond_to: tx,
                config,
            })
            .await?;
        Ok(RequestTicket { id, rx })
    }

    pub async fn send_event(
        &self,
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
    ) -> Result<(), async_channel::SendError<RuntimeCommand>> {
        let id = self.next_message_id();
        self.tx
            .send(RuntimeCommand::SendEvent {
                id,
                recipient,
                route_id,
                payload,
            })
            .await
    }

    pub async fn send_response(
        &self,
        id: MessageId,
        recipient: XID,
        payload: CBOR,
        kind: RecordKind,
    ) -> Result<(), async_channel::SendError<RuntimeCommand>> {
        self.tx
            .send(RuntimeCommand::SendResponse {
                id,
                recipient,
                payload,
                kind,
            })
            .await
    }
}

pub struct Runtime<P> {
    platform: P,
    config: RuntimeConfig,
    rx: async_channel::Receiver<RuntimeCommand>,
}

mod r#impl;

#[cfg(test)]
mod tests;

pub enum RuntimeCommand {
    RegisterPeer {
        peer: XID,
        signing_key: SigningPublicKey,
        encapsulation_key: EncapsulationPublicKey,
    },
    Connect {
        peer: XID,
    },
    SendRequest {
        id: MessageId,
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
        respond_to: oneshot::Sender<Result<CBOR, QlError>>,
        config: RequestConfig,
    },
    SendEvent {
        id: MessageId,
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
    },
    SendResponse {
        id: MessageId,
        recipient: XID,
        payload: CBOR,
        kind: RecordKind,
    },
    Incoming(Vec<u8>),
}

pub fn new_runtime<P: crate::platform::QlPlatform>(
    platform: P,
    config: RuntimeConfig,
) -> (Runtime<P>, RuntimeHandle) {
    let (tx, rx) = async_channel::unbounded();
    let next_message_id = Arc::new(AtomicU64::new(1));
    (
        Runtime {
            platform,
            config,
            rx,
        },
        RuntimeHandle {
            tx,
            next_message_id,
        },
    )
}

#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub peer: XID,
    pub signing_key: SigningPublicKey,
    pub encapsulation_key: EncapsulationPublicKey,
    pub session: PeerSession,
}

impl PeerRecord {
    pub fn new(
        peer: XID,
        signing_key: SigningPublicKey,
        encapsulation_key: EncapsulationPublicKey,
    ) -> Self {
        Self {
            peer,
            signing_key,
            encapsulation_key,
            session: PeerSession::Disconnected,
        }
    }
}

#[derive(Debug, Clone)]
pub enum PeerSession {
    Disconnected,
    Initiator {
        handshake_token: Token,
        hello: Hello,
        session_key: SymmetricKey,
        deadline: std::time::Instant,
        stage: InitiatorStage,
    },
    Responder {
        handshake_token: Token,
        hello: Hello,
        reply: HelloReply,
        secrets: ResponderSecrets,
        deadline: std::time::Instant,
    },
    Connected {
        session_key: SymmetricKey,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitiatorStage {
    WaitingHelloReply,
    WaitingConfirmAck,
}
