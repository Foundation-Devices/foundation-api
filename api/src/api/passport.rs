use flutter_rust_bridge::frb;
use minicbor_derive::{Decode, Encode};
use quantum_link_macros::quantum_link;

use crate::api::quantum_link::QuantumLink;

#[quantum_link]
pub enum PassportModel {
    #[n(0)]
    Gen1,
    #[n(1)]
    Gen2,
    #[n(2)]
    Prime,
}

#[derive(Debug, Clone, Encode, Decode, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct PassportFirmwareVersion(#[n(0)] pub String);

#[derive(Debug, Clone, Encode, Decode, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct PassportSerial(#[n(0)] pub String);

#[quantum_link]
pub enum PassportColor {
    #[n(0)]
    Light,
    #[n(1)]
    Dark,
}
