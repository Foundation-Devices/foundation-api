pub mod engine;
pub mod identity;
pub mod mux;
// pub mod rpc;
pub mod wire;

pub use wire::{PacketId, StreamId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub peer: bc_components::XID,
    pub signing_key: bc_components::MLDSAPublicKey,
    pub encapsulation_key: bc_components::MLKEMPublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QlError {
    #[error("invalid payload")]
    InvalidPayload,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("missing session")]
    MissingSession,
    #[error("no peer bound")]
    NoPeerBound,
    #[error("timeout")]
    Timeout,
    #[error("send failed")]
    SendFailed,
    #[error("stream closed {code:?}")]
    StreamClosed {
        target: wire::stream::CloseTarget,
        code: wire::stream::CloseCode,
        payload: Vec<u8>,
    },
    #[error("stream protocol error")]
    StreamProtocol,
    #[error("cancelled")]
    Cancelled,
}
