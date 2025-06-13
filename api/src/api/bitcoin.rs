use crate::quantum_link::QuantumLink;
use flutter_rust_bridge::frb;
use minicbor_derive::{Decode, Encode};
use quantum_link_macros::quantum_link;

#[quantum_link]
pub struct SignPsbt {
    #[n(0)]
    pub account_id: String,
    #[n(1)]
    pub psbt: Vec<u8>,
}

#[quantum_link]
pub struct AccountUpdate {
    #[n(0)]
    pub account_id: String,
    #[n(1)]
    pub update: Vec<u8>,
}

#[quantum_link]
pub struct BroadcastTransaction {
    #[n(0)]
    pub account_id: String,
    #[n(1)]
    pub psbt: Vec<u8>,
}
