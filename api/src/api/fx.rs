use quantum_link_macros::quantum_link;

#[quantum_link]
pub struct ExchangeRate {
    #[n(0)]
    pub currency_code: String,
    #[n(1)]
    pub rate: f32,
    #[n(2)]
    pub timestamp: u64,
}

#[quantum_link]
pub struct ExchangeRateHistory {
    #[n(0)]
    pub history: Vec<PricePoint>,
    #[n(1)]
    pub currency_code: String,
}

#[quantum_link]
pub struct PricePoint {
    #[n(0)]
    pub rate: f32,
    #[n(1)]
    pub timestamp: u64,
}
