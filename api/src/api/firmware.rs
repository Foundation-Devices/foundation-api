use crate::quantum_link::QuantumLink;
use flutter_rust_bridge::frb;
use minicbor_derive::{Decode, Encode};
use quantum_link_macros::quantum_link;

#[quantum_link]
pub struct FirmwareUpdateCheckRequest {
    #[n(0)]
    pub current_version: String,
}

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
    pub size: u32,
}

#[quantum_link]
pub struct FirmwareDownloadRequest {
    #[n(0)]
    pub version: String,
}

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
        total_chunks: u16,
    },
    #[n(2)]
    Chunk(#[n(0)] FirmwareChunk),
    #[n(3)]
    Error {
        #[n(0)]
        error: String,
    },
}

#[quantum_link]
pub struct FirmwareChunk {
    #[n(0)]
    pub index: u16,
    #[n(1)]
    pub data: Vec<u8>,
}

#[quantum_link]
pub enum FirmwareUpdateResult {
    #[n(0)]
    InstallSuccess {
        #[n(0)]
        installed_version: String,
    },
    #[n(1)]
    InstallFailed {
        #[n(0)]
        error: String,
    },
}
