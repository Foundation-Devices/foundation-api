use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    // codec errors
    UnexpectedEof,
    InvalidData,
    InvalidDiscriminant,
    InvalidRange,
    LengthOverflow,
    InvalidVarint,
    InvalidUtf8,
    InvalidPayload,

    // protocol validation
    InvalidRouteHeader,
    InvalidHandshakeId,
    InvalidPairingId,
    InvalidRemoteBundle,

    // cryptographic/session
    DecryptFailed,
    Expired,

    InvalidState,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnexpectedEof => "unexpected end of input",
            Self::InvalidData => "invalid data",
            Self::InvalidDiscriminant => "invalid discriminant",
            Self::InvalidRange => "invalid range",
            Self::LengthOverflow => "length overflow",
            Self::InvalidVarint => "invalid varint",
            Self::InvalidUtf8 => "invalid utf-8",
            Self::InvalidPayload => "invalid payload",
            Self::InvalidRouteHeader => "invalid route header",
            Self::InvalidHandshakeId => "invalid handshake id",
            Self::InvalidPairingId => "invalid pairing id",
            Self::InvalidRemoteBundle => "invalid remote bundle",
            Self::DecryptFailed => "decryption failed",
            Self::Expired => "expired",
            Self::InvalidState => "invalid state",
        };
        f.write_str(message)
    }
}

impl std::error::Error for Error {}

impl From<ql_codec::Error> for Error {
    fn from(error: ql_codec::Error) -> Self {
        match error {
            ql_codec::Error::InvalidData => Self::InvalidData,
            ql_codec::Error::UnexpectedEof => Self::UnexpectedEof,
            ql_codec::Error::InvalidDiscriminant => Self::InvalidDiscriminant,
            ql_codec::Error::InvalidRange => Self::InvalidRange,
            ql_codec::Error::LengthOverflow => Self::LengthOverflow,
            ql_codec::Error::InvalidVarint => Self::InvalidVarint,
            ql_codec::Error::InvalidUtf8 => Self::InvalidUtf8,
        }
    }
}
