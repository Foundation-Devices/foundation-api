//!
//! quantum link protocol wire format
//!

#![allow(clippy::too_many_arguments)]

mod bytes;
mod codec;
mod crypto;
mod encrypted;
mod encrypted_message;
mod error;
mod handshake;
mod header;
mod identity;
mod nonce;
mod pq;
mod record;
#[cfg(any(feature = "test-utils", test))]
mod testing;
mod varint;
mod xid;

pub use bytes::*;
pub use codec::*;
pub use crypto::*;
pub use encrypted::*;
pub use encrypted_message::*;
pub use error::*;
pub use handshake::*;
pub use header::*;
pub use identity::*;
pub use nonce::*;
pub use pq::*;
pub use record::*;
#[cfg(any(feature = "test-utils", test))]
pub use testing::*;
pub use varint::*;
pub use xid::*;

pub const QL_WIRE_VERSION: u8 = 1;
pub const ENCRYPTED_MESSAGE_AUTH_SIZE: usize = 16;

#[cfg(test)]
mod tests;
