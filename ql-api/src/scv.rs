use ql_rpc::Duplex;

use crate::{route, Error};

rpc! {
    pub struct ChallengeRequest {
        pub data: Vec<u8>,
    }
}

rpc! {
    pub enum ChallengeResponseResult {
        Success { data: Vec<u8> },
        Error { error: String },
    }
}

rpc! {
    pub enum VerificationResult {
        Success,
        Error { error: String },
        Failure,
    }
}

rpc! {
    pub enum SecurityCheckRemoteEvent {
        ChallengeRequest(ChallengeRequest),
        VerificationResult(VerificationResult),
    }
}

rpc! {
    pub enum SecurityCheckPassportEvent {
        Start,
        ChallengeResponse(ChallengeResponseResult),
    }
}

impl Duplex for route::SecurityCheck {
    type Error = Error;
    type InitiatorEvent = SecurityCheckPassportEvent;
    type ResponderEvent = SecurityCheckRemoteEvent;
}
