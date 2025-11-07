use quantum_link_macros::quantum_link;

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

//
// MAGIC BACKUPS
//

pub type SeedFingerprint = [u8; 32];

#[quantum_link]
#[derive(PartialEq, Eq)]
pub struct BackupChunk {
    #[n(0)]
    pub chunk_index: u32,
    #[n(1)]
    pub total_chunks: u32,
    #[n(2)]
    pub data: Vec<u8>,
}

impl BackupChunk {
    pub fn is_last(&self) -> bool {
        self.chunk_index == self.total_chunks - 1
    }
}

//
// CREATING BACKUP
//

// from prime -> envoy
#[quantum_link]
pub enum CreateMagicBackupEvent {
    #[n(0)]
    Start(#[n(0)] StartMagicBackup),
    #[n(1)]
    Chunk(#[n(0)] BackupChunk),
}

type Sha256Hash = [u8; 32];

#[quantum_link]
pub struct StartMagicBackup {
    #[n(0)]
    pub seed_fingerprint: SeedFingerprint,
    #[n(1)]
    pub total_chunks: u32,
    #[n(2)]
    pub hash: Sha256Hash,
}

// envoy -> prime
// error can be sent at any time
// success is expected at the end of the flow
#[quantum_link]
pub enum CreateMagicBackupResult {
    #[n(0)]
    Success,
    #[n(1)]
    Error(#[n(0)] String),
}

//
// RESTORING BACKUP
//

#[quantum_link]
pub struct RestoreMagicBackupRequest {
    #[n(0)]
    pub seed_fingerprint: SeedFingerprint,
    /// if 0, then go from start
    #[n(1)]
    pub resume_from_chunk: u32,
}

#[quantum_link]
pub enum RestoreMagicBackupEvent {
    // there is no backup found from the provided fingerprint
    #[n(0)]
    NoBackupFound,
    // envoy found a backup and is beginning transmission
    #[n(1)]
    Starting(#[n(0)] BackupMetadata),
    // a backup chunk
    #[n(2)]
    Chunk(#[n(0)] BackupChunk),
    // envoy failed
    #[n(3)]
    Error(#[n(0)] String),
}

#[quantum_link]
#[derive(PartialEq, Eq)]
pub struct BackupMetadata {
    #[n(0)]
    pub total_chunks: u32,
}

// sent from prime -> envoy
#[quantum_link]
pub enum RestoreMagicBackupResult {
    #[n(0)]
    Success,
    #[n(1)]
    Error(#[n(0)] String),
}
