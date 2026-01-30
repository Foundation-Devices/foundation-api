use std::time::Duration;

use bc_components::{EncapsulationPublicKey, SigningPublicKey, SymmetricKey, XID};

use crate::{platform::PeerStatus, wire::handshake::Hello};

pub struct RuntimeConfig {
    pub handshake_timeout: Duration,
}

impl RuntimeConfig {
    pub fn new(handshake_timeout: Duration) -> Self {
        Self { handshake_timeout }
    }
}

pub struct RuntimeHandle {
    tx: async_channel::Sender<RuntimeCommand>,
}

impl RuntimeHandle {
    pub async fn send_hello(
        &self,
        peer: XID,
        signing_key: SigningPublicKey,
        encapsulation_key: EncapsulationPublicKey,
    ) -> Result<(), async_channel::SendError<RuntimeCommand>> {
        self.tx
            .send(RuntimeCommand::SendHello {
                peer,
                signing_key,
                encapsulation_key,
            })
            .await
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
    local_xid: XID,
    rx: async_channel::Receiver<RuntimeCommand>,
}

mod r#impl;

pub enum RuntimeCommand {
    SendHello {
        peer: XID,
        signing_key: SigningPublicKey,
        encapsulation_key: EncapsulationPublicKey,
    },
    Incoming(Vec<u8>),
}

pub fn new_runtime<P: crate::platform::QlPlatform>(
    platform: P,
    config: RuntimeConfig,
    local_xid: XID,
) -> (Runtime<P>, RuntimeHandle) {
    let (tx, rx) = async_channel::unbounded();
    (
        Runtime {
            platform,
            config,
            local_xid,
            rx,
        },
        RuntimeHandle { tx },
    )
}

#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub signing_key: SigningPublicKey,
    pub encapsulation_key: EncapsulationPublicKey,
    pub status: PeerStatus,
    pub session_key: Option<SymmetricKey>,
    pub pending_hello: Option<Hello>,
    pub handshake_deadline: Option<std::time::Instant>,
}

impl PeerRecord {
    pub fn new(signing_key: SigningPublicKey, encapsulation_key: EncapsulationPublicKey) -> Self {
        Self {
            signing_key,
            encapsulation_key,
            status: PeerStatus::Disconnected,
            session_key: None,
            pending_hello: None,
            handshake_deadline: None,
        }
    }
}
