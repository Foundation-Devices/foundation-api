use ql_rpc::{Download, Notification, Request, Upload};

use crate::{route, Error};

rpc! {
    pub struct Shard(pub Vec<u8>);
}

rpc! {
    pub struct SeedFingerprint(pub [u8; 32]);
}

rpc! {
    pub struct BackupShardRequest {
        pub shard: Shard,
    }
}

rpc! {
    pub enum BackupShardResponse {
        Success,
        Error { error: String },
    }
}

impl Request for route::BackupShard {
    type Error = Error;
    type Request = BackupShardRequest;
    type Response = BackupShardResponse;
}

rpc! {
    pub struct RestoreShardRequest {
        pub seed_fingerprint: SeedFingerprint,
        pub timestamp: Option<u32>,
    }
}

rpc! {
    pub enum RestoreShardResponse {
        Success { shard: Shard },
        Error { error: String },
        NotFound,
    }
}

impl Request for route::RestoreShard {
    type Error = Error;
    type Request = RestoreShardRequest;
    type Response = RestoreShardResponse;
}

rpc! {
    pub struct EnvoyMagicBackupEnabledRequest {}
}

rpc! {
    pub struct EnvoyMagicBackupEnabledResponse {
        pub enabled: bool,
    }
}

impl Request for route::EnvoyMagicBackupEnabled {
    type Error = Error;
    type Request = EnvoyMagicBackupEnabledRequest;
    type Response = EnvoyMagicBackupEnabledResponse;
}

rpc! {
    pub struct PassportMagicBackupEnabledPayload {
        pub enabled: bool,
        pub seed_fingerprint: SeedFingerprint,
    }
}

impl Notification for route::PassportMagicBackupEnabled {
    type Error = Error;
    type Payload = PassportMagicBackupEnabledPayload;
}

rpc! {
    pub struct PassportMagicBackupStatusRequest {
        pub seed_fingerprint: SeedFingerprint,
        pub timestamp: Option<u32>,
    }
}

rpc! {
    pub struct PassportMagicBackupStatusResponse {
        pub shard_backup_found: bool,
    }
}

impl Request for route::PassportMagicBackupStatus {
    type Error = Error;
    type Request = PassportMagicBackupStatusRequest;
    type Response = PassportMagicBackupStatusResponse;
}

rpc! {
    pub struct UploadMagicBackupRequest {
        pub seed_fingerprint: SeedFingerprint,
        pub total_size: Option<u64>,
        pub hash: [u8; 32],
    }
}

rpc! {
    pub enum UploadMagicBackupResult {
        Success,
        Error { error: String },
    }
}

rpc! {
    pub struct UploadMagicBackupPartHeader {}
}

impl Upload for route::UploadMagicBackup {
    type Error = Error;
    type Request = UploadMagicBackupRequest;
    type PartHeader = UploadMagicBackupPartHeader;
    type Response = UploadMagicBackupResult;
}

rpc! {
    pub struct DownloadMagicBackupRequest {
        pub seed_fingerprint: SeedFingerprint,
    }
}

rpc! {
    pub enum DownloadMagicBackupHeader {
        Found(BackupMetadata),
        NotFound,
        Error { error: String },
    }
}

rpc! {
    pub struct BackupMetadata {
        pub total_size: Option<u64>,
    }
}

rpc! {
    pub struct DownloadMagicBackupPartHeader {}
}

impl Download for route::DownloadMagicBackup {
    type Error = Error;
    type Request = DownloadMagicBackupRequest;
    type ResponseHeader = DownloadMagicBackupHeader;
    type PartHeader = DownloadMagicBackupPartHeader;
}

rpc! {
    pub enum RestoreMagicBackupResult {
        Success,
        Error { error: String },
    }
}

impl Notification for route::RestoreMagicBackupComplete {
    type Error = Error;
    type Payload = RestoreMagicBackupResult;
}
