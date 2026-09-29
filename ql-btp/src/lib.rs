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

// v1 required its final header byte to be zero, so this tags v2 without growing the header
const V2_TAG: u8 = 0xb2;
const V2_TAG_BITS: u32 = (V2_TAG as u32) << 24;
const RECORD_LEN_MASK: u32 = 0x00ff_ffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1,
    V2,
}

pub fn packet_version(data: &[u8]) -> Option<Version> {
    match *data.get(HEADER_SIZE - 1)? {
        0 => Some(Version::V1),
        V2_TAG => Some(Version::V2),
        _ => None,
    }
}

ql_codec::codec! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Header {
        sequence: u16,
        index: u16,
        tagged_record_len: u32,
    }
}
