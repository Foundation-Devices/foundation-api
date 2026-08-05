use ql_rpc::{Download, Request};

use crate::{Empty, Error};

// COMMON TYPES

rpc! {
    #[derive(Copy)]
    pub struct AppVersion(pub u32, pub u32, pub u32);
}

rpc! {
    pub struct AppDetails {
        pub name: String,
        pub icon: String, // SVG?
        pub developer_id: Vec<u8>,
        pub app_id: Vec<u8>,
    }
}

// APP ROUTES

// SERVICE ROUTES

service_routes! {
    crate::service_id::APP_STORE => {
        RequestListApps: Request = 1,
        DownloadApp: Download = 2,
    }
}

rpc! {
    pub struct ListAppsResponse {
        pub apps: Vec<AppDetails>,
    }
}

impl Request for RequestListApps {
    type Error = Error;
    type Request = Empty;
    type Response = ListAppsResponse;
}

rpc! {
    pub struct DownloadAppParams {
        pub version: Option<String>,
    }
}

rpc! {
    pub struct DownloadAppHeader {
        pub version: String,
    }
}

rpc! {
    pub struct DownloadAppPartHeader {}
}

impl Download for DownloadApp {
    type Error = Error;
    type Request = DownloadAppParams;
    type ResponseHeader = DownloadAppHeader;
    type PartHeader = DownloadAppPartHeader;
}
