use {
    crate::api::QuantumLinkMessage,
    minicbor_derive::{Decode, Encode},
};

#[derive(Clone, Encode, Decode)]
pub struct Challenge {
    #[n(0)]
    id: String,
    #[n(1)]
    signature: String,
    #[n(2)]
    der_signature: String,
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


impl QuantumLinkMessage<Challenge> for Challenge {}


#[derive(Clone, Encode, Decode)]
pub struct ChallengeResponse {
    #[n(0)]
    challenge_id: String,
    #[n(1)]
    words: Vec<String>,
    #[n(2)]
    der_signature: String,
}

impl ChallengeResponse {
    pub fn new(challenge_id: String, words: Vec<String>, der_signature: String) -> Self {
        ChallengeResponse {
            challenge_id,
            words,
            der_signature
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

impl QuantumLinkMessage<ChallengeResponse> for ChallengeResponse {}
