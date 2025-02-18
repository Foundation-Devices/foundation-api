use {
    minicbor_derive::{Decode, Encode},
    quantum_link_macros::QuantumLink,
};
use crate::api::quantum_link::QuantumLink;

#[derive(Clone, Encode, Decode, QuantumLink, Debug)]
pub struct ExchangeRate {
    #[n(0)]
    currency_code: String,
    #[n(1)]
    rate: f32,
}

impl ExchangeRate {
    pub fn new(currency_code: &str, rate: f32) -> Self {
        Self {
            currency_code: currency_code.to_string(),
            rate,
        }
    }

    pub fn currency_code(&self) -> &str {
        &self.currency_code
    }

    pub fn rate(&self) -> f32 {
        self.rate
    }
}

//impl QuantumLinkMessage<ExchangeRate> for ExchangeRate {}
