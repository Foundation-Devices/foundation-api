use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    InvalidPayload,
    Expired,
    DecryptFailed,
    InvalidState,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPayload => "invalid payload",
            Self::Expired => "expired",
            Self::DecryptFailed => "decryption failed",
            Self::InvalidState => "invalid state",
        };
        f.write_str(message)
    }
}

impl std::error::Error for WireError {}
