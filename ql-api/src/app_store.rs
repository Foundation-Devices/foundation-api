use ql_rpc::{Download, Request, RouteId};

use crate::{codec::rpc, Error, Route};

rpc! {
    #[derive(Copy)]
    pub struct AppVersion(pub u32, pub u32, pub u32);
}

//
// LIST APPS
//

pub struct ListApps;

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

impl Request for ListApps {
    const ROUTE: RouteId = Route::ListApps.id();
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

pub struct AppDownload;

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

impl Download for AppDownload {
    const ROUTE: RouteId = Route::AppDownload.id();

    type Error = Error;

    type Request = AppDownloadRequest;

    type ResponseHeader = AppDownloadHeader;
}
