//! routing protocol for QuantumLink
//!
//! one transport connection can attach multiple authenticated QIDs
//! enable the `tokio` feature for the TCP client

use std::io;

#[cfg(feature = "tokio")]
mod client;
pub mod protocol;

#[cfg(feature = "tokio")]
pub use client::*;

pub const DEFAULT_ADDRESS: &str = "127.0.0.1:7447";
pub const MAX_RECORD_SIZE: usize = 8 * 1024;

fn invalid_data(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
