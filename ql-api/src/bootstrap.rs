use crate::{codec::rpc, Error, Route};

pub struct BootstrapQlv1;

impl ql_rpc::Request for BootstrapQlv1 {
    const ROUTE: ql_rpc::RouteId = Route::BootstrapQlv1.id();
    type Error = Error;
    type Request = BootstrapRequest;
    type Response = BootstrapResponse;
}

rpc! {
    pub struct BootstrapRequest {
        pub xid_document: Vec<u8>,
    }
}

rpc! {
    pub struct BootstrapResponse {
        pub xid_document: Vec<u8>,
    }
}
