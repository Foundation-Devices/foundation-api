pub use chunk::*;
pub use dechunk::*;

mod chunk;
mod dechunk;
#[cfg(test)]
mod tests;

use bytemuck::{Pod, Zeroable};
use consts::APP_MTU;

pub const HEADER_SIZE: usize = std::mem::size_of::<Header>();
pub const CHUNK_DATA_SIZE: usize = APP_MTU - HEADER_SIZE;

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Header {
    pub message_id: u16,
    pub index: u16,
    pub total_chunks: u16,
    pub data_len: u8,
    pub _padding: u8,
}

impl Header {
    #[inline]
    fn new(message_id: u16, index: u16, total_chunks: u16, data_len: u8) -> Self {
        Self {
            message_id,
            index,
            total_chunks,
            data_len,
            _padding: 0,
        }
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    /// Reads a header out of `bytes`, which does not have to be aligned:
    /// received packets are often a sub-slice of a larger transport buffer.
    #[inline]
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bytemuck::try_pod_read_unaligned::<Header>(bytes).ok()
    }
}
