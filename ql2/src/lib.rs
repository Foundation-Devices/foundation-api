mod id;
pub mod platform;
pub mod runtime;
pub mod wire;

pub use id::*;

#[cfg(test)]
mod tests;

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
    #[error("invalid handshake role")]
    InvalidRole,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("missing session for {0}")]
    MissingSession(bc_components::XID),
    #[error("unknown peer {0}")]
    UnknownPeer(bc_components::XID),
    #[error("timeout")]
    Timeout,
    #[error("send failed")]
    SendFailed,
    #[error("call rejected {code:?}")]
    CallRejected {
        id: CallId,
        code: wire::call::RejectCode,
    },
    #[error("call reset {code:?}")]
    CallReset {
        id: CallId,
        dir: wire::call::Direction,
        code: wire::call::ResetCode,
    },
    #[error("call protocol error")]
    CallProtocol { id: CallId },
    #[error("cancelled")]
    Cancelled,
}
