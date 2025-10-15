use flutter_rust_bridge::frb;
use minicbor_derive::{Decode, Encode};
use quantum_link_macros::quantum_link;

use crate::api::quantum_link::QuantumLink;

#[quantum_link]
pub struct Shard {
    #[n(0)]
    pub payload: Vec<u8>,
}

#[quantum_link]
pub struct BackupShardRequest(#[n(0)] pub Shard);

#[quantum_link]
pub enum BackupShardResponse {
    #[n(0)]
    Success,
    #[n(1)]
    Error(#[n(0)] String),
}

#[quantum_link]
pub struct RestoreShardRequest {
    #[n(0)]
    pub seed_fingerprint: [u8; 32],
}

#[quantum_link]
pub enum RestoreShardResponse {
    #[n(0)]
    Success(#[n(0)] Shard),
    #[n(1)]
    Error(#[n(0)] String),
    #[n(2)]
    NotFound(#[n(0)] String),
}

#[quantum_link]
pub struct MagicBackupEnabledRequest {}

#[quantum_link]
pub struct MagicBackupEnabledResponse {
    #[n(0)]
    pub enabled: bool,
}

pub type ShaHash = [u8; 32];

// restoring the backup

// sent in onboarding by prime once the seed is set
#[quantum_link]
pub struct BeginRestoreRequest {
    #[n(0)]
    seed_fingerprint: ShaHash,
}

// reply from envoy
#[quantum_link]
pub enum BeginRestoreResponse {
    #[n(0)]
    NotFound,
    #[n(1)]
    Restoring {
        #[n(0)]
        file_paths: Vec<String>,
    },
}

#[quantum_link]
pub struct RestoreFileRequest(#[n(0)] pub String);

// sent from envoy
#[quantum_link]
pub struct RestoreFileResponse(#[n(0)] pub MagicBackupFile);

// syncing (know which files to backup incrementally)

// sent from envoy on initial connection post onboarding
#[quantum_link]
pub struct BackupSyncRequest {
    #[n(0)]
    pub files: Vec<FileId>,
}

#[quantum_link]
pub struct FileId {
    #[n(0)]
    pub path: String,
    #[n(1)]
    pub sha256: ShaHash,
}

#[quantum_link]
pub struct BackupFile(#[n(0)] pub MagicBackupFile);

#[quantum_link]
pub struct MagicBackupFile {
    #[n(0)]
    pub file: Vec<u8>,
    #[n(1)]
    pub path: String,
    #[n(2)]
    pub sha256: ShaHash,
    #[n(3)]
    pub seed_fingerprint: ShaHash,
}
