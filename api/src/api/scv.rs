use crate::api::quantum_link::QuantumLink;
use flutter_rust_bridge::frb;
use {
    minicbor_derive::{Decode, Encode},
    quantum_link_macros::quantum_link,
};

#[quantum_link]
pub struct Challenge {
    #[n(0)]
    pub id: String,
    #[n(1)]
    pub signature: String,
    #[n(2)]
    pub der_signature: String,
}

impl Challenge {
    pub fn new(id: String, signature: String, der_signature: String) -> Self {
        Challenge {
            id,
            signature,
            der_signature,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }

    pub fn der_signature(&self) -> &str {
        &self.der_signature
    }
}

#[quantum_link]
pub struct ChallengeResponse {
    #[n(0)]
    pub challenge_id: String,
    #[n(1)]
    pub words: Vec<String>,
    #[n(2)]
    pub der_signature: String,
}

impl ChallengeResponse {
    pub fn new(challenge_id: String, words: Vec<String>, der_signature: String) -> Self {
        ChallengeResponse {
            challenge_id,
            words,
            der_signature,
        }
    }

    pub fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    pub fn words(&self) -> &Vec<String> {
        &self.words
    }

    pub fn der_signature(&self) -> &str {
        &self.der_signature
    }
}

#[quantum_link]
pub struct SecurityChallengeRequest {
    #[n(0)]
    pub data: Vec<u8>,
}

impl SecurityChallengeRequest {
    pub fn new(data: Vec<u8>) -> Self {
        SecurityChallengeRequest { data }
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

#[quantum_link]
pub struct SecurityChallengeResponse {
    #[n(0)]
    pub data: Vec<u8>,
}

impl SecurityChallengeResponse {
    pub fn new(data: Vec<u8>) -> Self {
        SecurityChallengeResponse { data }
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}
