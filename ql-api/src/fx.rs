use ql_rpc::{Request, Subscription};

use crate::Error;

// COMMON TYPES

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

// APP ROUTES

// SERVICE ROUTES

service_routes! {
    crate::service_id::FX => {
        SubscribeExchangeRate: Subscription = 1,
        RequestExchangeRateHistory: Request = 2,
    }
}

rpc! {
    pub struct ExchangeRateParams {
        pub currency_code: String,
    }
}

impl Subscription for SubscribeExchangeRate {
    type Error = Error;
    type Request = ExchangeRateParams;
    type Event = ExchangeRate;
}

rpc! {
    pub struct ExchangeRateHistoryParams {
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

impl Request for RequestExchangeRateHistory {
    type Error = Error;
    type Request = ExchangeRateHistoryParams;
    type Response = ExchangeRateHistory;
}
