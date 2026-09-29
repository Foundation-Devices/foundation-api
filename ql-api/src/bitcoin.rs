use ql_rpc::{Request, Subscription};

use crate::{Empty, Error};

// COMMON TYPES

rpc! {
    pub struct ActiveSeedFingerprint {
        pub fingerprint: String,
        pub has_passphrase: bool,
    }
}

// APP ROUTES

app_routes! {
    crate::app_id::BITCOIN => {
        RequestSignPsbt: Request = 1,
        SubscribeAccountUpdated: Subscription = 2,
        RequestPassportActiveSeedFingerprint: Request = 3,
        SubscribePassportActiveSeedFingerprint: Subscription = 4,
    }
}

rpc! {
    pub struct SignPsbtParams {
        pub account_id: String,
        pub psbt: Vec<u8>,
    }
}

rpc! {
    pub enum SignPsbtResponse {
        Signed { psbt: Vec<u8> },
        Rejected,
        Error { error: String },
    }
}

impl Request for RequestSignPsbt {
    type Error = Error;
    type Request = SignPsbtParams;
    type Response = SignPsbtResponse;
}

rpc! {
    pub struct AccountUpdatedEvent {
        pub account_id: String,
        pub update: Vec<u8>,
    }
}

impl Subscription for SubscribeAccountUpdated {
    type Error = Error;
    type Request = Empty;
    type Event = AccountUpdatedEvent;
}

impl Subscription for SubscribePassportActiveSeedFingerprint {
    type Error = Error;
    type Request = Empty;
    type Event = ActiveSeedFingerprint;
}

impl Request for RequestPassportActiveSeedFingerprint {
    type Error = Error;
    type Request = Empty;
    type Response = ActiveSeedFingerprint;
}

// SERVICE ROUTES

service_routes! {
    crate::service_id::BITCOIN => {
        RequestBroadcastTransaction: Request = 1,
    }
}

rpc! {
    pub struct BroadcastTransactionParams {
        pub account_id: String,
        pub psbt: Vec<u8>,
    }
}

rpc! {
    pub enum BroadcastTransactionResponse {
        Broadcast { txid: String },
        Error { error: String },
    }
}

impl Request for RequestBroadcastTransaction {
    type Error = Error;
    type Request = BroadcastTransactionParams;
    type Response = BroadcastTransactionResponse;
}
