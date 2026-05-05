use ql_rpc::{request::Request, Download, RouteId, Subscription};

use crate::{codec::rpc, Error, Route};

// Echo request-response benchmark
pub struct Echo;

impl Request for Echo {
    type Error = Error;
    type Request = EchoRequest;
    type Response = EchoResponse;

    const ROUTE: RouteId = Route::Echo.id();
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
pub struct BytesBenchmark;

impl Subscription for BytesBenchmark {
    type Error = Error;
    type Event = BenchmarkEvent;
    type Request = BenchmarkRequest;

    const ROUTE: ql_rpc::RouteId = Route::BytesBenchmark.id();
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
pub struct DownloadBenchmark;

impl Download for DownloadBenchmark {
    type Error = Error;
    type Request = DownloadBenchmarkRequest;
    type ResponseHeader = DownloadBenchmarkHeader;

    const ROUTE: RouteId = Route::DownloadBenchmark.id();
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
