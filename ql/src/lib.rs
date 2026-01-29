use dcbor::CBOR;

mod encrypt;
pub mod handle;
pub mod identity;
pub mod platform;
pub mod router;
pub mod runtime;
pub mod wire;

pub trait QlCodec: Into<CBOR> + TryFrom<CBOR, Error = dcbor::Error> + Sized {}

impl<T> QlCodec for T where T: Into<CBOR> + TryFrom<CBOR, Error = dcbor::Error> + Sized {}

pub trait RequestResponse: QlCodec {
    const ID: u64;
    type Response: QlCodec;
}

pub trait Event: QlCodec {
    const ID: u64;
}

#[derive(Debug, thiserror::Error)]
pub enum QlError {
    #[error(transparent)]
    Decode(#[from] dcbor::Error),
    #[error("message expired")]
    Expired(bc_components::ARID),
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
    #[error("session reset")]
    SessionReset,
    #[error("timeout")]
    Timeout,
    #[error("send failed")]
    SendFailed,
    #[error("nack {0:?}")]
    Nack(wire::Nack),
    #[error("cancelled")]
    Cancelled,
}

#[cfg(test)]
mod tests;
