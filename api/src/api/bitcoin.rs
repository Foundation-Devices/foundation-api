use quantum_link_macros::quantum_link;
use crate::quantum_link::QuantumLink;
use {
    minicbor_derive::{Decode, Encode},
};
use flutter_rust_bridge::frb;


#[quantum_link]
pub struct Psbt {
    #[n(0)]
    pub descriptor: String,
    #[n(1)]
    pub psbt: String,
}

#[quantum_link]
pub struct SyncUpdate {
    #[n(0)]
    pub descriptor: String,
    #[n(1)]
    pub psbt: Vec<u8>,
}


