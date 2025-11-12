use quantum_link_macros::quantum_link;

use crate::{
    api::passport::{PassportFirmwareVersion, PassportModel, PassportSerial},
    passport::PassportColor,
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
    #[n(4)]
    pub onboarding_complete: bool,
}

#[quantum_link]
pub struct PairingRequest {
    #[n(0)]
    pub xid_document: Vec<u8>,
    #[n(1)]
    pub device_name: String,
}
