use quantum_link_macros::quantum_link;

#[quantum_link]
pub struct ExchangeRate {
    #[n(0)]
    pub currency_code: String,
    #[n(1)]
    pub rate: f32,
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
