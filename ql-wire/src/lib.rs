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
mod xid;

pub use bytes::*;
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
pub use xid::*;

pub const QL_WIRE_VERSION: u8 = 2;
pub const ENCRYPTED_MESSAGE_AUTH_SIZE: usize = 16;

#[cfg(test)]
mod tests;
