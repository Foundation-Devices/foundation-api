use {
    crate::api::{
        passport::{PassportFirmwareVersion, PassportModel, PassportSerial},
        QuantumLinkMessage,
    },
    minicbor_derive::{Decode, Encode},
};
use quantum_link_macros::QuantumLinkMessage;

#[derive(Encode, Decode, QuantumLinkMessage, Debug)]
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


#[derive(Encode, Decode, QuantumLinkMessage, Debug)]
pub struct PairingRequest {}
