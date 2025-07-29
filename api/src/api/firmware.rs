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
    pub diff_count: u8,
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
        diff_index: u8,
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
    pub diff_index: u8,
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
