use ql_rpc::Request;

use crate::{Empty, Error};

// APP ROUTES

// SERVICE ROUTES

service_routes! {
    crate::service_id::TIME => {
        RequestTimezone: Request = 1,
        RequestCurrentTime: Request = 2,
    }
}

rpc! {
    pub struct TimezoneResponse {
        pub offset_minutes: i32,
        pub zone: String,
    }
}

impl Request for RequestTimezone {
    type Error = Error;
    type Request = Empty;
    type Response = TimezoneResponse;
}

rpc! {
    pub struct CurrentTimeResponse {
        pub server_time_millis: u64,
    }
}

impl Request for RequestCurrentTime {
    type Error = Error;
    type Request = Empty;
    type Response = CurrentTimeResponse;
}
