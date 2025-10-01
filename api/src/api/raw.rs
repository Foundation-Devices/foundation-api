use {
    crate::api::quantum_link::QuantumLink,
    flutter_rust_bridge::frb,
    minicbor_derive::{Decode, Encode},
    quantum_link_macros::quantum_link,
};

#[quantum_link]
pub struct RawData {
    #[n(0)]
    pub payload: Vec<u8>,
}
