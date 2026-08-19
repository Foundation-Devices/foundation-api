//!
//! QuantumLink protocol wire format
//!

#![allow(clippy::too_many_arguments)]

mod crypto;
mod encrypted;
mod encrypted_message;
mod error;
mod handshake;
mod header;
mod identity;
mod pq;
mod qid;
mod record;
#[cfg(any(feature = "test-utils", test))]
mod testing;

pub use crypto::*;
pub use encrypted::*;
pub use encrypted_message::*;
pub use error::*;
pub use handshake::*;
pub use header::*;
pub use identity::*;
pub use pq::*;
pub use qid::*;
pub use record::*;
#[cfg(any(feature = "test-utils", test))]
pub use testing::*;

pub const QL_WIRE_VERSION: u8 = 2;
pub const ENCRYPTED_MESSAGE_AUTH_SIZE: usize = 16;

#[cfg(test)]
mod tests;
