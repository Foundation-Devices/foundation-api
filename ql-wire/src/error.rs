use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WireError {
    #[error("invalid payload")]
    InvalidPayload,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("expired")]
    Expired,
    #[error("decryption failed")]
    DecryptFailed,
}
