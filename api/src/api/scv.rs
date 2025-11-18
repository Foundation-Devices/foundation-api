use quantum_link_macros::quantum_link;

#[quantum_link]
pub enum SecurityCheck {
    // Envoy to Prime: Initial challenge
    #[n(0)]
    ChallengeRequest(#[n(0)] ChallengeRequest),

    // Prime to Envoy: Response to the challenge
    #[n(1)]
    ChallengeResponse(#[n(0)] ChallengeResponseResult),

    // Envoy to Prime: Verification result
    // only send if ChallengeResponse was successful
    #[n(2)]
    VerificationResult(#[n(0)] VerificationResult),
}

#[quantum_link]
pub struct ChallengeRequest {
    #[cbor(n(0), with = "minicbor::bytes")]
    pub data: Vec<u8>,
}

#[quantum_link]
pub enum ChallengeResponseResult {
    #[n(0)]
    Success {
        #[cbor(n(0), with = "minicbor::bytes")]
        data: Vec<u8>,
    },
    #[n(1)]
    Error {
        #[n(0)]
        error: String,
    },
}

#[quantum_link]
pub enum VerificationResult {
    #[n(0)]
    Success,
    #[n(1)]
    Error {
        #[n(0)]
        error: String,
    },
}
