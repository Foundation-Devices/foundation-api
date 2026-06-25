use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    InvalidPayload,
    InvalidRouteHeader,
    InvalidHandshakeMeta,
    InvalidPairingId,
    InvalidRemoteBundle,
    InvalidTransportParams,
    Expired,
    DecryptFailed,
    InvalidState,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPayload => "invalid payload",
            Self::InvalidRouteHeader => "invalid route header",
            Self::InvalidHandshakeMeta => "invalid handshake meta",
            Self::InvalidPairingId => "invalid pairing id",
            Self::InvalidRemoteBundle => "invalid remote bundle",
            Self::InvalidTransportParams => "invalid transport params",
            Self::Expired => "expired",
            Self::DecryptFailed => "decryption failed",
            Self::InvalidState => "invalid state",
        };
        f.write_str(message)
    }
}

impl std::error::Error for WireError {}
