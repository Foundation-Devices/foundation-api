use flutter_rust_bridge::frb;
use minicbor_derive::{Decode, Encode};
use quantum_link_macros::quantum_link;

use crate::api::quantum_link::QuantumLink;

#[quantum_link]
pub struct RawData {
    #[n(0)]
    pub payload: Vec<u8>,
}
