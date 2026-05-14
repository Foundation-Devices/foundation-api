use ql_rpc::{Notification, Request, Subscription};

use crate::{route, Error};

rpc! {
    #[PartialEq]
    pub struct ExchangeRate {
        pub currency_code: String,
        pub rate: f32,
        pub timestamp: u64,
    }
}

rpc! {
    #[PartialEq]
    pub struct PricePoint {
        pub rate: f32,
        pub timestamp: u64,
    }
}

rpc! {
    pub struct ExchangeRateHistoryRequest {
        pub currency_code: String,
    }
}

rpc! {
    #[PartialEq]
    pub struct ExchangeRateHistory {
        pub history: Vec<PricePoint>,
        pub currency_code: String,
    }
}

impl Notification for route::ExchangeRateUpdate {
    type Error = Error;
    type Payload = ExchangeRate;
}

rpc! {
    pub struct ExchangeRateSubscriptionRequest {
        pub currency_code: String,
    }
}

impl Subscription for route::ExchangeRateSubscription {
    type Error = Error;
    type Request = ExchangeRateSubscriptionRequest;
    type Event = ExchangeRate;
}

impl Request for route::ExchangeRateHistory {
    type Error = Error;
    type Request = ExchangeRateHistoryRequest;
    type Response = ExchangeRateHistory;
}

rpc! {
    pub struct PassportFiatPreferencePayload {
        pub currency_code: String,
    }
}

impl Notification for route::PassportFiatPreference {
    type Error = Error;
    type Payload = PassportFiatPreferencePayload;
}

rpc! {
    pub struct PassportFiatPreferenceRequest {}
}

rpc! {
    pub struct PassportFiatPreferenceResponse {
        pub currency_code: String,
    }
}

impl Request for route::PassportFiatPreferenceRequest {
    type Error = Error;
    type Request = PassportFiatPreferenceRequest;
    type Response = PassportFiatPreferenceResponse;
}
