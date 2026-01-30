use std::time::Duration;

use bc_components::{EncapsulationPublicKey, SigningPublicKey, SymmetricKey, XID};

use crate::{crypto::handshake::ResponderSecrets, wire::handshake::{Hello, HelloReply}};

pub struct RuntimeConfig {
    pub handshake_timeout: Duration,
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
        Self { handshake_timeout }
    }
}

#[derive(Clone)]
pub struct RuntimeHandle {
    tx: async_channel::Sender<RuntimeCommand>,
}

impl RuntimeHandle {
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
    Incoming(Vec<u8>),
}

pub fn new_runtime<P: crate::platform::QlPlatform>(
    platform: P,
    config: RuntimeConfig,
) -> (Runtime<P>, RuntimeHandle) {
    let (tx, rx) = async_channel::unbounded();
    (
        Runtime {
            platform,
            config,
            rx,
        },
        RuntimeHandle { tx },
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
