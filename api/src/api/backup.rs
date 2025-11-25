pub use backup_shard::{ShardV0, ShardVersion};
use quantum_link_macros::quantum_link;

#[quantum_link]
#[repr(transparent)]
pub struct Shard(pub Vec<u8>);

#[quantum_link]
#[repr(transparent)]
pub struct SeedFingerprint(pub [u8; 32]);

#[quantum_link]
pub struct BackupShardRequest {
    #[n(0)]
    pub shard: Shard,
}

#[quantum_link]
pub enum BackupShardResponse {
    #[n(0)]
    Success,
    #[n(1)]
    Error {
        #[n(0)]
        error: String,
    },
}

#[quantum_link]
pub struct RestoreShardRequest {
    #[n(0)]
    pub seed_fingerprint: SeedFingerprint,
}

#[quantum_link]
pub enum RestoreShardResponse {
    #[n(0)]
    Success {
        #[n(0)]
        shard: Shard,
    },
    #[n(1)]
    Error {
        #[n(0)]
        error: String,
    },
    #[n(2)]
    NotFound,
}

#[quantum_link]
pub struct EnvoyMagicBackupEnabledRequest {}

#[quantum_link]
pub struct EnvoyMagicBackupEnabledResponse {
    #[n(0)]
    pub enabled: bool,
}

#[quantum_link]
pub struct PrimeMagicBackupEnabled {
    #[n(0)]
    pub enabled: bool,
    #[n(1)]
    pub seed_fingerprint: SeedFingerprint,
}

#[quantum_link]
pub struct PrimeMagicBackupStatusRequest {
    #[n(0)]
    pub seed_fingerprint: SeedFingerprint,
}

#[quantum_link]
pub struct PrimeMagicBackupStatusResponse {
    #[n(0)]
    pub shard_backup_found: bool,
}

//
// MAGIC BACKUPS
//

#[quantum_link]
#[derive(Eq)]
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
    Start(StartMagicBackup),
    #[n(1)]
    Chunk(BackupChunk),
}

#[quantum_link]
pub struct StartMagicBackup {
    #[n(0)]
    pub seed_fingerprint: SeedFingerprint,
    #[n(1)]
    pub total_chunks: u32,
    #[n(2)]
    pub hash: [u8; 32],
}

// envoy -> prime
// error can be sent at any time
// success is expected at the end of the flow
#[quantum_link]
pub enum CreateMagicBackupResult {
    #[n(0)]
    Success,
    #[n(1)]
    Error {
        #[n(0)]
        error: String,
    },
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
    NotFound,
    // envoy found a backup and is beginning transmission
    #[n(1)]
    Starting(BackupMetadata),
    // a backup chunk
    #[n(2)]
    Chunk(BackupChunk),
    // envoy failed
    #[n(3)]
    Error {
        #[n(0)]
        error: String,
    },
}

#[quantum_link]
#[derive(Eq)]
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
    Error {
        #[n(0)]
        error: String,
    },
}
