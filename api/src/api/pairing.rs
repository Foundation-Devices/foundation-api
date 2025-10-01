use {
    crate::{
        api::{
            passport::{PassportFirmwareVersion, PassportModel, PassportSerial},
            quantum_link::QuantumLink,
        },
        passport::PassportColor,
    },
    flutter_rust_bridge::frb,
    minicbor_derive::{Decode, Encode},
    quantum_link_macros::quantum_link,
};

#[quantum_link]
pub struct PairingResponse {
    #[n(0)]
    pub passport_model: PassportModel,
    #[n(1)]
    pub passport_firmware_version: PassportFirmwareVersion,
    #[n(2)]
    pub passport_serial: PassportSerial,
    #[n(3)]
    pub passport_color: PassportColor,
}

#[quantum_link]
pub struct PairingRequest {
    #[n(0)]
    pub xid_document: Vec<u8>,
}
