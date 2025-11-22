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
    Available(FirmwareUpdateAvailable),
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
    Starting(FirmwareUpdateAvailable),
    // envoy is downloading the update
    #[n(2)]
    Downloading,
    // envoy is sending a chunk for an update patch
    #[n(3)]
    Chunk(FirmwareChunk),
    // envoy failed
    #[n(5)]
    Error {
        #[n(0)]
        error: String,
    },
}

#[quantum_link]
#[derive(Eq)]
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

impl FirmwareChunk {
    pub fn is_last(&self) -> bool {
        self.patch_index == self.total_patches - 1 && self.chunk_index == self.total_chunks - 1
    }
}

#[quantum_link]
pub enum FirmwareInstallEvent {
    #[n(0)]
    UpdateVerified,
    #[n(1)]
    Installing,
    #[n(2)]
    Rebooting,
    #[n(3)]
    Success {
        #[n(0)]
        installed_version: String,
    },
    #[n(4)]
    Error {
        #[n(0)]
        error: String,
        #[n(1)]
        stage: InstallErrorStage,
    },
}

#[quantum_link]
pub enum InstallErrorStage {
    #[n(0)]
    Download,
    #[n(1)]
    Verify,
    #[n(2)]
    Install,
}
