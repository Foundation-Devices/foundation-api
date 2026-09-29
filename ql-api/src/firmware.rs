use ql_rpc::{Download, Request, Subscription};

use crate::{Empty, Error};

// COMMON TYPES

rpc! {
    pub struct FirmwareUpdateAvailable {
        pub version: String,
        pub changelog: String,
        pub timestamp: u32,
        pub total_size: u32,
        pub patch_count: u8,
    }
}

// APP ROUTES

app_routes! {
    crate::app_id::UPDATE => {
        SubscribeFirmwareInstallStatus: Subscription = 1,
    }
}

rpc! {
    pub enum InstallErrorStage {
        Download,
        Verify,
        Install,
    }
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

impl Subscription for SubscribeFirmwareInstallStatus {
    type Error = Error;
    type Request = Empty;
    type Event = FirmwareInstallEvent;
}

// SERVICE ROUTES

service_routes! {
    crate::service_id::FIRMWARE => {
        RequestCheckFirmwareUpdate: Request = 1,
        DownloadFirmware: Download = 2,
    }
}

rpc! {
    pub struct FirmwareUpdateCheckParams {
        pub current_version: String,
    }
}

rpc! {
    pub enum FirmwareUpdateCheckResponse {
        Available(FirmwareUpdateAvailable),
        NotAvailable,
    }
}

impl Request for RequestCheckFirmwareUpdate {
    type Error = Error;
    type Request = FirmwareUpdateCheckParams;
    type Response = FirmwareUpdateCheckResponse;
}

rpc! {
    pub struct DownloadFirmwareParams {
        pub current_version: String,
    }
}

rpc! {
    pub enum DownloadFirmwareHeader {
        Available(FirmwareUpdateAvailable),
        NotAvailable,
        Error { error: String },
    }
}

rpc! {
    pub struct DownloadFirmwarePartHeader {
        pub patch_name: String,
        pub size_bytes: u64,
    }
}

impl Download for DownloadFirmware {
    type Error = Error;
    type Request = DownloadFirmwareParams;
    type ResponseHeader = DownloadFirmwareHeader;
    type PartHeader = DownloadFirmwarePartHeader;
}
