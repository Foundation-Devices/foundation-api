mod id;
pub mod handshake;
pub mod pairing;
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
}
