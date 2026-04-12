//! quantum link rpc protocol traits and framing helpers.

pub(crate) mod codec;
mod error;
mod router;
pub mod rpc;

pub use codec::{ReadValueStep, RpcCodec, ValueReader};
pub use error::*;
pub use router::*;
pub use rpc::*;

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
    pub const CANCELLED: Self = Self(0);
    pub const REFUSED: Self = Self(1);
    pub const TIMEOUT: Self = Self(2);
    pub const LIMIT: Self = Self(3);
    pub const UNKNOWN_ROUTE: Self = Self(4);

    pub const fn into_inner(self) -> u16 {
        self.0
    }
}
