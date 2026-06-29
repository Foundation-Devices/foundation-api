use ql_keyos::AppId;
use ql_rpc::{Request, Subscription};

use crate::{Empty, Error};

// COMMON TYPES

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

// APP ROUTES

app_routes! {
    crate::app_id::SYSTEM => {
        RequestPassportDetails: Request = 1,
        SubscribePassportDetails: Subscription = 2,
        RequestPassportFiatPreference: Request = 3,
        SubscribePassportFiatPreference: Subscription = 4,
        SubscribeAppActivity: Subscription = 5,
    }
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

impl Request for RequestPassportDetails {
    type Error = Error;
    type Request = Empty;
    type Response = PassportDetailsResponse;
}

impl Subscription for SubscribePassportDetails {
    type Error = Error;
    type Request = Empty;
    type Event = PassportDetailsResponse;
}

rpc! {
    pub struct PassportFiatPreferenceResponse {
        pub currency_code: String,
    }
}

impl Request for RequestPassportFiatPreference {
    type Error = Error;
    type Request = Empty;
    type Response = PassportFiatPreferenceResponse;
}

rpc! {
    pub struct PassportFiatPreferenceEvent {
        pub currency_code: String,
    }
}

impl Subscription for SubscribePassportFiatPreference {
    type Error = Error;
    type Request = Empty;
    type Event = PassportFiatPreferenceEvent;
}

rpc! {
    pub enum AppActivityEvent {
        Opened(AppId),
        Closed(AppId),
    }
}

impl Subscription for SubscribeAppActivity {
    type Error = Error;
    type Request = Empty;
    type Event = AppActivityEvent;
}

// SERVICE ROUTES
