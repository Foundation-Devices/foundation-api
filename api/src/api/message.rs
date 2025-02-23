use crate::quantum_link::QuantumLink;
use minicbor_derive::{Decode, Encode};
use quantum_link_macros::quantum_link;
use crate::firmware::FirmwareUpdate;
use crate::fx::ExchangeRate;
use crate::pairing::{PairingRequest, PairingResponse};
use crate::status::{DeviceStatus, EnvoyStatus};

#[quantum_link]
pub struct EnvoyMessage {
    #[n(0)]
    message: QuantumLinkMessage,
    #[n(1)]
    timestamp: u32,
}

impl EnvoyMessage {
    pub fn new(message: QuantumLinkMessage, timestamp: u32) -> Self {
        Self { message, timestamp }
    }

    pub fn message(&self) -> &QuantumLinkMessage {
        &self.message
    }

    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }
}

#[quantum_link]
pub struct PassportMessage {
    #[n(0)]
    message: QuantumLinkMessage,
    #[n(1)]
    status: DeviceStatus,
}

impl PassportMessage {
    pub fn new(message: QuantumLinkMessage, status: DeviceStatus) -> Self {
        Self { message, status }
    }

    pub fn message(&self) -> &QuantumLinkMessage {
        &self.message
    }

    pub fn status(&self) -> &DeviceStatus {
        &self.status
    }
}

#[quantum_link]
pub enum QuantumLinkMessage {
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