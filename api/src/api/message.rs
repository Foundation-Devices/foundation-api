use super::onboarding::OnboardingState;
use crate::backup::Shard;
use crate::bitcoin::*;
use crate::firmware::{FirmwarePayload, FirmwareUpdate};
use crate::fx::ExchangeRate;
use crate::pairing::{PairingRequest, PairingResponse};
use crate::quantum_link::QuantumLink;
use crate::scv::{SecurityChallengeMessage, SecurityProofMessage};
use crate::status::{DeviceStatus, EnvoyStatus};
use flutter_rust_bridge::frb;
use minicbor_derive::{Decode, Encode};
use quantum_link_macros::quantum_link;

#[quantum_link]
pub struct EnvoyMessage {
    #[n(0)]
    pub message: QuantumLinkMessage,
    #[n(1)]
    pub timestamp: u32,
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
    pub message: QuantumLinkMessage,
    #[n(1)]
    pub status: DeviceStatus,
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
    #[n(6)]
    OnboardingState(#[n(0)] OnboardingState),
    #[n(7)]
    SignPsbt(#[n(0)] SignPsbt),
    #[n(8)]
    AccountUpdate(#[n(0)] AccountUpdate),
    #[n(9)]
    FirmwarePayload(#[n(0)] FirmwarePayload),
    #[n(10)]
    BroadcastTransaction(#[n(0)] BroadcastTransaction),
    #[n(11)]
    SecurityChallengeMessage(#[n(0)] SecurityChallengeMessage),
    #[n(12)]
    SecurityProofMessage(#[n(0)] SecurityProofMessage),
    #[n(13)]
    Shard(#[n(0)] Shard),
}
