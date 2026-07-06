//! Shared QuantumLink primitive types.

mod varint;
pub use varint::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ResetCode(pub u16);

impl ResetCode {
    /// operation was explicitly cancelled
    pub const CANCELLED: Self = Self(0);
    /// local reader/writer/call handle was dropped before completion
    pub const DROPPED: Self = Self(1);
    /// session/connection became unavailable while the stream was active
    pub const DISCONNECTED: Self = Self(2);
    /// local internal error
    pub const INTERNAL: Self = Self(3);
    /// malformed stream data, invalid framing, or invalid RPC sequence
    pub const PROTOCOL: Self = Self(4);
    /// application codec failed to encode/decode payload
    pub const CODEC: Self = Self(5);
    /// stream/request was intentionally refused before processing
    pub const REFUSED: Self = Self(6);
    /// operation timed out
    pub const TIMEOUT: Self = Self(7);
    /// configured or encoded size limit was exceeded
    pub const LIMIT: Self = Self(8);
    /// route identifier was unknown
    pub const UNKNOWN_ROUTE: Self = Self(9);
}

impl std::fmt::Display for ResetCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::CANCELLED => f.write_str("cancelled"),
            Self::DROPPED => f.write_str("dropped"),
            Self::DISCONNECTED => f.write_str("disconnected"),
            Self::INTERNAL => f.write_str("internal"),
            Self::PROTOCOL => f.write_str("protocol"),
            Self::CODEC => f.write_str("codec"),
            Self::REFUSED => f.write_str("refused"),
            Self::TIMEOUT => f.write_str("timeout"),
            Self::LIMIT => f.write_str("limit"),
            Self::UNKNOWN_ROUTE => f.write_str("unknown route"),
            Self(code) => write!(f, "{code}"),
        }
    }
}

/// origin of a stream reset: either we triggered it locally or the peer sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResetOrigin {
    /// the reset code originated from the peer
    Peer,
    /// the reset code originated from local logic
    Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct QID(pub [u8; Self::SIZE]);

impl QID {
    pub const SIZE: usize = 16;
}

varint_wrapper!(
    /// Identifier for a stream within a QL session.
    StreamId
);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamInfo {
    pub qid: QID,
    pub stream_id: StreamId,
    pub header: Box<[u8]>,
}
