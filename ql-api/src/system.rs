use ql_keyos::{AppId, PeerPermissions};
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
        RequestPeerPermissions: Request = 6,
        RequestInstallPeerBundles: Request = 7,
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

rpc! {
    pub struct PeerPermissionsParams(pub PeerPermissions);
}

rpc! {
    pub enum PeerPermissionsResponse {
        Updated,
        Denied,
    }
}

impl Request for RequestPeerPermissions {
    type Error = Error;
    type Request = PeerPermissionsParams;
    type Response = PeerPermissionsResponse;
}

rpc! {
    pub struct InstallPeerBundlesParams {
        pub router: Vec<u8>,
        pub peers: Vec<Vec<u8>>,
    }
}

rpc! {
    pub enum InstallPeerBundlesResponse {
        Installed,
        Rejected,
    }
}

impl Request for RequestInstallPeerBundles {
    type Error = Error;
    type Request = InstallPeerBundlesParams;
    type Response = InstallPeerBundlesResponse;
}

// SERVICE ROUTES
