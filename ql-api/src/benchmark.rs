use ql_rpc::{request::Request, Download, Subscription};

use crate::{route, Error};

// Echo request-response benchmark
impl Request for route::Echo {
    type Error = Error;
    type Request = EchoRequest;
    type Response = EchoResponse;
}

rpc! {
    pub struct EchoRequest {
        pub message: String,
    }
}

rpc! {
    pub struct EchoResponse {
        pub message: String,
    }
}

// Byte-stream subscription benchmark
impl Subscription for route::BytesBenchmark {
    type Error = Error;
    type Event = BenchmarkEvent;
    type Request = BenchmarkRequest;
}

rpc! {
    pub struct BenchmarkRequest {
        pub length: u32,
    }
}

rpc! {
    pub struct BenchmarkEvent {
        pub bytes: Vec<u8>,
    }
}

// Raw-body download benchmark
impl Download for route::DownloadBenchmark {
    type Error = Error;
    type Request = DownloadBenchmarkRequest;
    type ResponseHeader = DownloadBenchmarkHeader;
    type PartHeader = DownloadBenchmarkPartHeader;
}

rpc! {
    pub struct DownloadBenchmarkRequest {
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
