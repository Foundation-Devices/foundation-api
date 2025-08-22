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
    pub total_size: u32,
    #[n(4)]
    pub patch_count: u8,
}

// From Prime to Envoy
#[quantum_link]
pub struct FirmwareFetchRequest {
    #[n(0)]
    pub current_version: String,
}

// From Envoy to Prime
#[quantum_link]
pub enum FirmwareFetchEvent {
    // there is no update available from the provided prime version
    #[n(0)]
    UpdateNotAvailable,
    // envoy has found an update, and will begin transmission
    #[n(1)]
    Starting(#[n(0)] FirmwareUpdateAvailable),
    // envoy is downloading the update
    #[n(2)]
    Downloading,
    // envoy is sending a chunk for an update patch
    #[n(3)]
    Chunk(#[n(0)] FirmwareChunk),
    // envoy has sent all the update patches
    #[n(4)]
    Complete,
    // envoy failed
    #[n(5)]
    Error(#[n(0)] String),
}

#[quantum_link]
#[derive(PartialEq, Eq)]
pub struct FirmwareChunk {
    #[n(0)]
    pub patch_index: u8,
    #[n(1)]
    pub total_patches: u8,
    #[n(2)]
    pub chunk_index: u16,
    #[n(3)]
    pub total_chunks: u16,
    #[n(4)]
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
    total_patches: u8,
    patch_bytes: &[u8],
    chunk_size: usize,
) -> impl Iterator<Item = FirmwareChunk> + '_ {
    let chunks = patch_bytes.chunks(chunk_size);
    let total_chunks = chunks.len() as u16;
    chunks
        .enumerate()
        .map(move |(chunk_index, chunk_data)| FirmwareChunk {
            patch_index,
            total_patches,
            chunk_index: chunk_index as u16,
            total_chunks,
            data: chunk_data.to_vec(),
        })
}

#[test]
fn test_split_update_into_chunks_non_flush() {
    let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let patch_index = 42;
    let total_patches = 5;
    let chunk_size = 3;

    let chunks: Vec<_> =
        split_update_into_chunks(patch_index, total_patches, &data, chunk_size).collect();

    assert_eq!(chunks.len(), 4);

    assert_eq!(
        chunks[0],
        FirmwareChunk {
            patch_index,
            total_patches,
            chunk_index: 0,
            total_chunks: 4,
            data: vec![1, 2, 3],
        }
    );

    assert_eq!(
        chunks[1],
        FirmwareChunk {
            patch_index,
            total_patches,
            chunk_index: 1,
            total_chunks: 4,
            data: vec![4, 5, 6],
        }
    );

    assert_eq!(
        chunks[2],
        FirmwareChunk {
            patch_index,
            total_patches,
            chunk_index: 2,
            total_chunks: 4,
            data: vec![7, 8, 9],
        }
    );

    assert_eq!(
        chunks[3],
        FirmwareChunk {
            patch_index,
            total_patches,
            chunk_index: 3,
            total_chunks: 4,
            data: vec![10],
        }
    );
}
