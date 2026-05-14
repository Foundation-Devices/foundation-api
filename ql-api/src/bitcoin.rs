use ql_rpc::{Notification, Request};

use crate::{route, Error};

rpc! {
    pub struct SignPsbtRequest {
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

impl Request for route::SignPsbt {
    type Error = Error;
    type Request = SignPsbtRequest;
    type Response = SignPsbtResponse;
}

rpc! {
    pub struct BroadcastTransactionRequest {
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

impl Request for route::BroadcastTransaction {
    type Error = Error;
    type Request = BroadcastTransactionRequest;
    type Response = BroadcastTransactionResponse;
}

rpc! {
    pub struct AccountUpdatePayload {
        pub account_id: String,
        pub update: Vec<u8>,
    }
}

impl Notification for route::AccountUpdate {
    type Error = Error;
    type Payload = AccountUpdatePayload;
}

rpc! {
    pub struct ActiveSeedFingerprint {
        pub fingerprint: String,
        pub has_passphrase: bool,
    }
}

impl Notification for route::PassportActiveSeedFingerprint {
    type Error = Error;
    type Payload = ActiveSeedFingerprint;
}

rpc! {
    pub struct PassportActiveSeedFingerprintRequest {}
}

impl Request for route::GetPassportActiveSeedFingerprint {
    type Error = Error;
    type Request = PassportActiveSeedFingerprintRequest;
    type Response = ActiveSeedFingerprint;
}
