//! Shared QuantumLink primitive types.

mod varint;
pub use varint::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct StreamCloseCode(pub u16);

impl StreamCloseCode {
    /// the stream was aborted intentionally before graceful completion
    pub const CANCELLED: Self = Self(0);
    /// local internal error
    pub const INTERNAL: Self = Self(1);
    /// request was refused
    pub const REFUSED: Self = Self(2);
    /// operation timed out
    pub const TIMEOUT: Self = Self(3);
    /// configured limit was exceeded
    pub const LIMIT: Self = Self(4);
    /// route identifier was unknown
    pub const UNKNOWN_ROUTE: Self = Self(5);
}

impl std::fmt::Display for StreamCloseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct QID(pub [u8; Self::SIZE]);

impl QID {
    pub const SIZE: usize = 16;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ServiceId(pub [u8; 16]);

impl ServiceId {
    pub const SIZE: usize = size_of::<ServiceId>();
}

impl std::fmt::Display for ServiceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

varint_wrapper!(RouteId);
varint_wrapper!(StreamId);
