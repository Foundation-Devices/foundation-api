pub mod engine;
pub mod identity;
// pub mod rpc;
pub mod runtime;
pub mod wire;

pub use wire::{PacketId, StreamId};

// #[cfg(test)]
// mod tests;

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
    #[error("stream rejected {code:?}")]
    StreamRejected { code: wire::stream::RejectCode },
    #[error("stream reset {code:?}")]
    StreamReset {
        dir: wire::stream::Direction,
        code: wire::stream::ResetCode,
    },
    #[error("stream protocol error")]
    StreamProtocol,
    #[error("cancelled")]
    Cancelled,
}
