//! quantum link rpc protocol traits and framing helpers.

use bytes::Buf;

pub(crate) mod codec;
mod error;
pub mod header;
pub mod rpc;

pub use error::*;
pub use rpc::*;

pub const RPC_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct MethodId(pub u64);

pub trait RpcCodec: Sized {
    type Error;

    fn encode_value(&self, out: &mut Vec<u8>) -> Result<(), Self::Error>;
    fn decode_value<B: Buf>(bytes: &mut B) -> Result<Self, Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inbound<'a> {
    pub header: header::RpcHeader,
    pub body: &'a [u8],
}

pub fn parse_inbound(bytes: &[u8]) -> Result<Inbound<'_>, RpcError> {
    let (header, body) = header::RpcHeader::decode(bytes)?;
    Ok(Inbound { header, body })
}
