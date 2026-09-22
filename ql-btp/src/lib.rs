pub use chunk::*;
pub use dechunk::*;

mod chunk;
mod dechunk;
#[cfg(test)]
mod tests;

use consts::APP_MTU;

pub const MAX_RECORD_SIZE: usize = 128 * 1024;
pub const HEADER_SIZE: usize = size_of::<u16>() * 2 + size_of::<u32>();
pub const CHUNK_DATA_SIZE: usize = APP_MTU - HEADER_SIZE;

ql_codec::codec! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Header {
        sequence: u16,
        index: u16,
        /// length in bytes
        record_len: u32,
    }
}
