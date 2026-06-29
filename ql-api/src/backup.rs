use ql_rpc::{Download, Request, Subscription, Upload};

use crate::{Empty, Error};

// COMMON TYPES

rpc! {
    pub struct Shard(pub Vec<u8>);
}

rpc! {
    pub struct SeedFingerprint(pub [u8; 32]);
}

// APP ROUTES

app_routes! {
    crate::app_id::BACKUP => {
        SubscribePassportMagicBackupEnabled: Subscription = 1,
        SubscribeMagicBackupRestoreCompleted: Subscription = 2,
    }
}

rpc! {
    pub struct PassportMagicBackupEnabled {
        pub enabled: bool,
        pub seed_fingerprint: SeedFingerprint,
    }
}

impl Subscription for SubscribePassportMagicBackupEnabled {
    type Error = Error;
    type Request = Empty;
    type Event = PassportMagicBackupEnabled;
}

rpc! {
    pub enum MagicBackupRestoreResult {
        Success,
        Error { error: String },
    }
}

impl Subscription for SubscribeMagicBackupRestoreCompleted {
    type Error = Error;
    type Request = Empty;
    type Event = MagicBackupRestoreResult;
}

// SERVICE ROUTES

service_routes! {
    crate::service_id::BACKUP => {
        RequestBackupShard: Request = 1,
        RequestRestoreShard: Request = 2,
        RequestPassportMagicBackupStatus: Request = 3,
        UploadMagicBackup: Upload = 4,
        DownloadMagicBackup: Download = 5,
    }
}

rpc! {
    pub struct BackupShardParams {
        pub shard: Shard,
    }
}

rpc! {
    pub enum BackupShardResponse {
        Success,
        Error { error: String },
    }
}

impl Request for RequestBackupShard {
    type Error = Error;
    type Request = BackupShardParams;
    type Response = BackupShardResponse;
}

rpc! {
    pub struct RestoreShardParams {
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

impl Request for RequestRestoreShard {
    type Error = Error;
    type Request = RestoreShardParams;
    type Response = RestoreShardResponse;
}

rpc! {
    pub struct PassportMagicBackupStatusParams {
        pub seed_fingerprint: SeedFingerprint,
        pub timestamp: Option<u32>,
    }
}

rpc! {
    pub struct PassportMagicBackupStatusResponse {
        pub shard_backup_found: bool,
    }
}

impl Request for RequestPassportMagicBackupStatus {
    type Error = Error;
    type Request = PassportMagicBackupStatusParams;
    type Response = PassportMagicBackupStatusResponse;
}

rpc! {
    pub struct UploadMagicBackupParams {
        pub seed_fingerprint: SeedFingerprint,
        pub total_size: Option<u64>,
        pub hash: [u8; 32],
    }
}

rpc! {
    pub enum UploadMagicBackupResponse {
        Success,
        Error { error: String },
    }
}

rpc! {
    pub struct UploadMagicBackupPartHeader {}
}

impl Upload for UploadMagicBackup {
    type Error = Error;
    type Request = UploadMagicBackupParams;
    type PartHeader = UploadMagicBackupPartHeader;
    type Response = UploadMagicBackupResponse;
}

rpc! {
    pub struct DownloadMagicBackupParams {
        pub seed_fingerprint: SeedFingerprint,
    }
}

rpc! {
    pub struct BackupMetadata {
        pub total_size: Option<u64>,
    }
}

rpc! {
    pub enum DownloadMagicBackupHeader {
        Found(BackupMetadata),
        NotFound,
        Error { error: String },
    }
}

impl Download for DownloadMagicBackup {
    type Error = Error;
    type Request = DownloadMagicBackupParams;
    type ResponseHeader = DownloadMagicBackupHeader;
    type PartHeader = Empty;
}
