//! quantum link rpc protocol traits and framing helpers.

pub(crate) mod codec;
mod error;
mod router;
pub mod rpc;
mod stream;

pub use codec::{ReadValueStep, RpcCodec, ValueReader};
pub use error::*;
pub use router::*;
pub use rpc::*;
pub use stream::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RouteId(pub u32);

impl RouteId {
    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    pub const fn into_inner(self) -> u32 {
        self.0
    }
}

impl From<u32> for RouteId {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct StreamCloseCode(pub u16);

impl StreamCloseCode {
    /// operation was cancelled
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

    pub const fn into_inner(self) -> u16 {
        self.0
    }
}
