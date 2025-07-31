use crate::quantum_link::QuantumLink;
use flutter_rust_bridge::frb;
use minicbor_derive::{Decode, Encode};
use quantum_link_macros::quantum_link;

// From Prime to Envoy
#[quantum_link]
pub struct FirmwareUpdateCheckRequest {
    #[n(0)]
    pub current_version: String,
}

// From Envoy to Prime
#[quantum_link]
pub enum FirmwareUpdateCheckResponse {
    #[n(0)]
    Available(#[n(0)] FirmwareUpdateAvailable),
    #[n(1)]
    NotAvailable,
}

#[quantum_link]
pub struct FirmwareUpdateAvailable {
    #[n(0)]
    pub version: String,
    #[n(1)]
    pub changelog: String,
    #[n(2)]
    pub timestamp: u32,
    #[n(3)]
    pub size: u32,
    #[n(4)]
    pub patch_count: u8,
}

#[quantum_link]
pub struct FirmwareDownloadRequest {
    #[n(0)]
    pub version: String,
}

// From Envoy to Prime
#[quantum_link]
pub enum FirmwareDownloadResponse {
    #[n(0)]
    EnvoyDownloadProgress {
        #[n(0)]
        progress: f32,
    },
    #[n(1)]
    Start {
        #[n(0)]
        patch_index: u8,
        #[n(1)]
        total_chunks: u16,
    },
    #[n(2)]
    Chunk(#[n(0)] FirmwareChunk),
    #[n(3)]
    Error(#[n(0)] String),
}

#[quantum_link]
pub struct FirmwareChunk {
    #[n(0)]
    pub patch_index: u8,
    #[n(1)]
    pub chunk_index: u16,
    #[n(2)]
    pub data: Vec<u8>,
}

#[quantum_link]
pub enum FirmwareUpdateResult {
    #[n(0)]
    Success {
        #[n(0)]
        installed_version: String,
    },
    #[n(1)]
    Error(#[n(0)] String),
}

pub fn split_update_into_chunks(
    patch_index: u8,
    patch_bytes: &[u8],
    chunk_size: usize,
) -> impl Iterator<Item = FirmwareChunk> + '_ {
    patch_bytes
        .chunks(chunk_size)
        .enumerate()
        .map(move |(chunk_index, chunk_data)| FirmwareChunk {
            patch_index,
            chunk_index: chunk_index as u16,
            data: chunk_data.to_vec(),
        })
}

#[test]
fn test_split_update_into_chunks_non_flush() {
    let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let patch_index = 42;
    let chunk_size = 3;

    let chunks: Vec<_> = split_update_into_chunks(patch_index, &data, chunk_size).collect();

    assert_eq!(chunks.len(), 4);

    assert_eq!(chunks[0].patch_index, 42);
    assert_eq!(chunks[0].chunk_index, 0);
    assert_eq!(chunks[0].data, vec![1, 2, 3]);

    assert_eq!(chunks[1].patch_index, 42);
    assert_eq!(chunks[1].chunk_index, 1);
    assert_eq!(chunks[1].data, vec![4, 5, 6]);

    assert_eq!(chunks[2].patch_index, 42);
    assert_eq!(chunks[2].chunk_index, 2);
    assert_eq!(chunks[2].data, vec![7, 8, 9]);

    assert_eq!(chunks[3].patch_index, 42);
    assert_eq!(chunks[3].chunk_index, 3);
    assert_eq!(chunks[3].data, vec![10]);
}
