pub mod handshake;
pub mod platform;
pub mod runtime;
pub mod wire;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QlError {
    #[error("invalid payload")]
    InvalidPayload,
    #[error("invalid handshake role")]
    InvalidRole,
    #[error("invalid signature")]
    InvalidSignature,
}
