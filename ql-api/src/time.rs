use ql_rpc::Request;

use crate::{route, Error};

rpc! {
    pub struct TimezoneRequest {}
}

rpc! {
    pub struct TimezoneResponse {
        pub offset_minutes: i32,
        pub zone: String,
    }
}

impl Request for route::Timezone {
    type Error = Error;
    type Request = TimezoneRequest;
    type Response = TimezoneResponse;
}

rpc! {
    pub struct CurrentTimeRequest {}
}

rpc! {
    pub struct CurrentTimeResponse {
        pub server_time_millis: u64,
    }
}

impl Request for route::CurrentTime {
    type Error = Error;
    type Request = CurrentTimeRequest;
    type Response = CurrentTimeResponse;
}
