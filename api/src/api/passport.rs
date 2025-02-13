use {
    crate::QuantumLinkMessage,
    minicbor_derive::{Decode, Encode},
    quantum_link_macros::QuantumLinkMessage,
};

#[derive(Debug, Clone, Encode, Decode, QuantumLinkMessage)]
pub enum PassportModel {
    #[n(0)]
    Gen1,
    #[n(1)]
    Gen2,
    #[n(2)]
    Prime,
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct PassportFirmwareVersion(#[n(0)] pub String);

#[derive(Debug, Clone, Encode, Decode)]
pub struct PassportSerial(#[n(0)] pub String);
