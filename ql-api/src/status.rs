use ql_rpc::{Notification, Request};

use crate::{route, Error};

rpc! {
    pub enum PassportModel {
        Gen1,
        Gen2,
        Prime,
    }
}

rpc! {
    pub struct PassportFirmwareVersion(pub String);
}

rpc! {
    pub struct PassportSerial(pub String);
}

rpc! {
    pub enum PassportColor {
        Light,
        Dark,
    }
}

rpc! {
    pub struct PassportDetailsRequest {}
}

rpc! {
    pub struct PassportDetailsResponse {
        pub device_name: String,
        pub model: PassportModel,
        pub firmware_version: PassportFirmwareVersion,
        pub serial: PassportSerial,
        pub color: PassportColor,
        pub onboarding_complete: bool,
    }
}

impl Request for route::PassportDetails {
    type Error = Error;
    type Request = PassportDetailsRequest;
    type Response = PassportDetailsResponse;
}

impl Notification for route::PassportDetailsUpdated {
    type Error = Error;
    type Payload = PassportDetailsResponse;
}
