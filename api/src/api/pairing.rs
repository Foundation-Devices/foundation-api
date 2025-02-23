use {
    crate::api::passport::{PassportFirmwareVersion, PassportModel, PassportSerial},
    minicbor_derive::{Decode, Encode},
};
use quantum_link_macros::QuantumLink;
use crate::api::quantum_link::QuantumLink;

#[derive(Clone, Encode, Decode, QuantumLink, Debug, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
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


#[derive(Clone, Encode, Decode, QuantumLink, Debug, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct PairingRequest {}
