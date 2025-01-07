use foundation_urtypes::registry::HDKeyRef;
use minicbor_derive::{Decode, Encode};
use {
    crate::api::passport::{PassportFirmwareVersion, PassportModel, PassportSerial},
};
use crate::api::QuantumLinkMessage;

#[derive(Encode, Decode)]
pub struct PairingResponse<'a> {
    #[n(0)] pub passport_model: PassportModel,
    #[n(1)] pub passport_firmware_version: PassportFirmwareVersion,
    #[n(2)] pub passport_serial: PassportSerial,
    #[b(3)] pub hdkey: HDKeyRef<'a>,
}

impl QuantumLinkMessage<PairingResponse<'_>> for PairingResponse<'_> {}

#[derive(Encode, Decode)]
pub struct PairingRequest {}

impl QuantumLinkMessage<PairingRequest> for PairingRequest {}

