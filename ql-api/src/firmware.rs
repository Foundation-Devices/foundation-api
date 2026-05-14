use ql_rpc::{Download, Notification, Request};

use crate::{route, Error};

rpc! {
    pub struct FirmwareUpdateCheckRequest {
        pub current_version: String,
    }
}

rpc! {
    pub enum FirmwareUpdateCheckResponse {
        Available(FirmwareUpdateAvailable),
        NotAvailable,
    }
}

rpc! {
    pub struct FirmwareUpdateAvailable {
        pub version: String,
        pub changelog: String,
        pub timestamp: u32,
        pub total_size: u32,
        pub patch_count: u8,
    }
}

impl Request for route::FirmwareUpdateCheck {
    type Error = Error;
    type Request = FirmwareUpdateCheckRequest;
    type Response = FirmwareUpdateCheckResponse;
}

rpc! {
    pub struct FirmwareDownloadRequest {
        pub current_version: String,
    }
}

rpc! {
    pub enum FirmwareDownloadHeader {
        Available(FirmwareUpdateAvailable),
        NotAvailable,
        Error { error: String },
    }
}

rpc! {
    pub struct FirmwareDownloadPartHeader {
        pub patch_name: String,
        pub size_bytes: u64,
    }
}

impl Download for route::FirmwareDownload {
    type Error = Error;
    type Request = FirmwareDownloadRequest;
    type ResponseHeader = FirmwareDownloadHeader;
    type PartHeader = FirmwareDownloadPartHeader;
}

rpc! {
    pub enum FirmwareInstallEvent {
        Installing,
        Rebooting,
        Success {
            installed_version: String,
        },
        Error {
            error: String,
            stage: InstallErrorStage,
        },
    }
}

rpc! {
    pub enum InstallErrorStage {
        Download,
        Verify,
        Install,
    }
}

impl Notification for route::FirmwareInstallStatus {
    type Error = Error;
    type Payload = FirmwareInstallEvent;
}
