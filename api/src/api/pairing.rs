use {
    crate::api::passport::{PassportFirmwareVersion, PassportModel, PassportSerial},
    minicbor_derive::{Decode, Encode},
};
use quantum_link_macros::quantum_link;
use crate::api::quantum_link::QuantumLink;
use flutter_rust_bridge::frb;


#[quantum_link]
pub struct PairingResponse {
    #[n(0)]
    pub passport_model: PassportModel,
    #[n(1)]
    pub passport_firmware_version: PassportFirmwareVersion,
    #[n(2)]
    pub passport_serial: PassportSerial,
    #[b(3)]
    pub descriptor: String,
}

#[quantum_link]
pub struct PairingRequest {
    #[n(0)]
    pub xid_document: Vec<u8>,
}
