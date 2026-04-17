//! quantum link rpc protocol traits and framing helpers.

mod chunk_queue;
pub(crate) mod codec;
mod error;
mod framed_value;
mod route_id;
mod router;
mod rpc;
mod stream;

pub use chunk_queue::ChunkQueue;
pub use codec::RpcCodec;
pub use error::*;
use framed_value::*;
pub use route_id::RouteId;
pub use router::*;
pub use rpc::*;
pub use stream::*;

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
