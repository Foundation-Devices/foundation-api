use ql_rpc::Duplex;

use crate::Error;

// APP ROUTES

// SERVICE ROUTES

service_routes! {
    crate::service_id::SCV => {
        RunSecurityCheck: Duplex = 1,
    }
}

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
    pub enum RunSecurityCheckResponderEvent {
        ChallengeRequest(ChallengeRequest),
        VerificationResult(VerificationResult),
    }
}

rpc! {
    pub enum RunSecurityCheckInitiatorEvent {
        Start,
        ChallengeResponse(ChallengeResponseResult),
    }
}

impl Duplex for RunSecurityCheck {
    type Error = Error;
    type InitiatorEvent = RunSecurityCheckInitiatorEvent;
    type ResponderEvent = RunSecurityCheckResponderEvent;
}
