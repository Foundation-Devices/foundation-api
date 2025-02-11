use minicbor_derive::{Decode, Encode};
use quantum_link_macros::QuantumLinkMessage;
use crate::firmware::FirmwareUpdate;
use crate::fx::ExchangeRate;
use crate::status::{DeviceStatus, EnvoyStatus};
use crate::pairing::PairingResponse;
use crate::pairing::PairingRequest;
use crate::QuantumLinkMessage;

#[derive(Encode, Decode, QuantumLinkMessage)]
pub enum QuantumLinkMessages {
    #[n(0)]
    ExchangeRate(#[n(0)] ExchangeRate),
    #[n(1)]
    FirmwareUpdate(#[n(0)] FirmwareUpdate),
    #[n(2)]
    DeviceStatus(#[n(0)] DeviceStatus),
    #[n(3)]
    EnvoyStatus(#[n(0)] EnvoyStatus),
    #[n(4)]
    PairingResponse(#[n(0)] PairingResponse),
    #[n(5)]
    PairingRequest(#[n(0)] PairingRequest),
}