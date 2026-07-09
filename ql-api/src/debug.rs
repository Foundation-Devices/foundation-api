use ql_rpc::{request::Request, Download};

use crate::Error;

// APP ROUTES

app_routes! {
    crate::app_id::DEBUG => {
        RequestPassportEcho: Request = 1,
        DownloadPassportBenchmark: Download = 2,
    }
}

rpc! {
    pub struct EchoParams {
        pub message: String,
    }
}

rpc! {
    pub struct EchoResponse {
        pub message: String,
    }
}

rpc! {
    pub struct DownloadBenchmarkParams {
        pub length: u64,
    }
}

rpc! {
    pub struct DownloadBenchmarkHeader {
        pub hash: Vec<u8>,
    }
}

rpc! {
    pub struct DownloadBenchmarkPartHeader {}
}

impl Request for RequestPassportEcho {
    type Error = Error;
    type Request = EchoParams;
    type Response = EchoResponse;
}

impl Download for DownloadPassportBenchmark {
    type Error = Error;
    type Request = DownloadBenchmarkParams;
    type ResponseHeader = DownloadBenchmarkHeader;
    type PartHeader = DownloadBenchmarkPartHeader;
}

// SERVICE ROUTES

service_routes! {
    crate::service_id::DEBUG => {
        RequestEcho: Request = 1,
        DownloadBenchmark: Download = 3,
    }
}

impl Request for RequestEcho {
    type Error = Error;
    type Request = EchoParams;
    type Response = EchoResponse;
}

impl Download for DownloadBenchmark {
    type Error = Error;
    type Request = DownloadBenchmarkParams;
    type ResponseHeader = DownloadBenchmarkHeader;
    type PartHeader = DownloadBenchmarkPartHeader;
}
