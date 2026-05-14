use ql_rpc::{Download, Request};

use crate::{route, Error};

rpc! {
    #[derive(Copy)]
    pub struct AppVersion(pub u32, pub u32, pub u32);
}

//
// LIST APPS
//

rpc! {
    pub struct ListAppsRequest {
        //
    }
}

rpc! {
    pub struct ListAppsResponse {
        pub apps: Vec<AppDetails>,
    }
}

rpc! {
    pub struct AppDetails {
        pub name: String,
        pub icon: String, // SVG?
        pub developer_id: Vec<u8>,
        pub app_id: Vec<u8>,
    }
}

impl Request for route::ListApps {
    type Error = Error;
    type Request = ListAppsRequest;
    type Response = ListAppsResponse;
}

//
// APP DOWNLOAD
//
// download a single tar file that contains:
// - app.elf
// - manifest.json

rpc! {
    pub struct AppDownloadRequest {
        pub version: Option<String>,
    }
}

rpc! {
    pub struct AppDownloadHeader {
        pub version: String,
    }
}

rpc! {
    pub struct AppDownloadPartHeader {}
}

impl Download for route::AppDownload {
    type Error = Error;

    type Request = AppDownloadRequest;

    type ResponseHeader = AppDownloadHeader;

    type PartHeader = AppDownloadPartHeader;
}
