//! quantum link rpc protocol traits and framing helpers.

use bytes::{Buf, BufMut};

pub(crate) mod codec;
mod error;
pub mod rpc;

pub use error::*;
pub use rpc::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct MethodId(pub u32);

pub trait RpcCodec: Sized {
    type Error;

    fn encode_value<B: BufMut + ?Sized>(&self, out: &mut B) -> Result<(), Self::Error>;
    fn decode_value<B: Buf>(bytes: &mut B) -> Result<Self, Self::Error>;
}
