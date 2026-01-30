pub mod crypto;
mod id;
pub mod platform;
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
    #[error("nack {nack:?}")]
    Nack {
        id: MessageId,
        nack: wire::message::Nack,
    },
    #[error("cancelled")]
    Cancelled,
}
