use super::onboarding::OnboardingState;
use crate::api::raw::RawData;
use crate::backup::Shard;
use crate::bitcoin::*;
use crate::firmware::{
    FirmwareDownloadRequest, FirmwareDownloadResponse, FirmwareUpdateCheckRequest,
    FirmwareUpdateCheckResponse, FirmwareUpdateResult,
};
use crate::fx::ExchangeRate;
use crate::pairing::{PairingRequest, PairingResponse};
use crate::quantum_link::QuantumLink;
use crate::scv::{SecurityChallengeRequest, SecurityChallengeResponse};
use crate::status::{DeviceStatus, EnvoyStatus};
use flutter_rust_bridge::frb;
use minicbor_derive::{Decode, Encode};
use quantum_link_macros::quantum_link;

#[quantum_link]
pub struct RawMessage {
    #[n(0)]
    pub payload: Vec<u8>,
}

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
    FirmwareUpdateCheckRequest(#[n(0)] FirmwareUpdateCheckRequest),
    #[n(2)]
    FirmwareUpdateCheckResponse(#[n(0)] FirmwareUpdateCheckResponse),
    #[n(3)]
    FirmwareDownloadRequest(#[n(0)] FirmwareDownloadRequest),
    #[n(4)]
    FirmwareDownloadResponse(#[n(0)] FirmwareDownloadResponse),
    #[n(5)]
    FirmwareUpdateResult(#[n(0)] FirmwareUpdateResult),
    #[n(6)]
    DeviceStatus(#[n(0)] DeviceStatus),
    #[n(7)]
    EnvoyStatus(#[n(0)] EnvoyStatus),
    #[n(8)]
    PairingRequest(#[n(0)] PairingRequest),
    #[n(9)]
    PairingResponse(#[n(0)] PairingResponse),
    #[n(10)]
    OnboardingState(#[n(0)] OnboardingState),
    #[n(11)]
    SignPsbt(#[n(0)] SignPsbt),
    #[n(13)]
    BroadcastTransaction(#[n(0)] BroadcastTransaction),
    #[n(12)]
    AccountUpdate(#[n(0)] AccountUpdate),
    #[n(14)]
    SecurityChallengeRequest(#[n(0)] SecurityChallengeRequest),
    #[n(15)]
    SecurityChallengeResponse(#[n(0)] SecurityChallengeResponse),
    #[n(16)]
    Shard(#[n(0)] Shard),
    #[n(17)]
    RawData(#[n(0)] RawData),
}
