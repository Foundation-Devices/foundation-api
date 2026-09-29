//! routing protocol for QuantumLink
//!
//! ```text
//!
//! 1. encrypt the TCP connection
//! client -> router: IK1 using an ephemeral identity
//! router -> client: IK2
//! client -> router: encrypted confirmation
//!
//! 2. attach identity B to the same connection
//! connection -> router: B's IK1
//! router -> connection: B's IK2 + encrypted cookie
//! connection -> router: cookie + B's proof
//!
//! 3. proof valid: route records for B to the connection
//! ```
//!
//! the cookie holds B's QID, attachment key, connection, and expiry. the router
//! keeps no pending attachment state. replaying IK1 causes work but cannot attach B

#[cfg(feature = "tokio")]
use std::io;

#[cfg(feature = "tokio")]
mod client;
pub mod protocol;

#[cfg(feature = "tokio")]
pub use client::*;

pub const DEFAULT_ADDRESS: &str = "127.0.0.1:7447";
pub const MAX_RECORD_SIZE: usize = 8 * 1024;

#[cfg(feature = "tokio")]
fn invalid_data(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
