mod encrypt;
pub mod handle;
mod id;
pub mod identity;
pub mod platform;
pub mod router;
pub mod runtime;
pub mod wire;

pub use id::*;

pub trait QlCodec: Into<dcbor::CBOR> + TryFrom<dcbor::CBOR, Error = dcbor::Error> {}
impl<T> QlCodec for T where T: Into<dcbor::CBOR> + TryFrom<dcbor::CBOR, Error = dcbor::Error> {}

pub trait RequestResponse: QlCodec {
    const ID: RouteId;
    type Response: QlCodec;
}

pub trait Event: QlCodec {
    const ID: RouteId;
}

#[derive(Debug, thiserror::Error)]
pub enum QlError {
    #[error(transparent)]
    Decode(#[from] dcbor::Error),
    #[error("invalid payload")]
    InvalidPayload,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("missing session for {0}")]
    MissingSession(bc_components::XID),
    #[error("unknown peer {0}")]
    UnknownPeer(bc_components::XID),
    #[error("session init collision")]
    SessionInitCollision,
    #[error("stale session")]
    StaleSession,
    #[error("session reset")]
    SessionReset,
    #[error("timeout")]
    Timeout,
    #[error("send failed")]
    SendFailed,
    #[error("nack {nack:?}")]
    Nack { id: MessageId, nack: wire::Nack },
    #[error("cancelled")]
    Cancelled,
}

#[cfg(test)]
mod tests;
