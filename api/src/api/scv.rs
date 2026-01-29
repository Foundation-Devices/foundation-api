use quantum_link_macros::quantum_link;

#[quantum_link]
pub enum SecurityCheck {
    // Envoy to Prime: Initial challenge
    #[n(0)]
    ChallengeRequest(ChallengeRequest),

    // Prime to Envoy: Response to the challenge
    #[n(1)]
    ChallengeResponse(ChallengeResponseResult),

    // Envoy to Prime: Verification result
    // only send if ChallengeResponse was successful
    #[n(2)]
    VerificationResult(VerificationResult),
}

#[quantum_link]
pub struct ChallengeRequest {
    #[n(0)]
    pub data: Vec<u8>,
}

#[quantum_link]
pub enum ChallengeResponseResult {
    #[n(0)]
    Success {
        #[n(0)]
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
    // Error due to Envoy not being able to perform the verification
    #[n(1)]
    Error {
        #[n(0)]
        error: String,
    },
    // Actual failure indicating device has been tampered with
    #[n(2)]
    Failure,
}
