use quantum_link_macros::quantum_link;

use super::onboarding::OnboardingState;
use crate::{
    api::raw::RawData,
    backup::{
        BackupShardRequest, BackupShardResponse, MagicBackupEnabledRequest,
        MagicBackupEnabledResponse, RestoreShardRequest, RestoreShardResponse,
    },
    bitcoin::*,
    firmware::{
        FirmwareFetchEvent, FirmwareFetchRequest, FirmwareUpdateCheckRequest,
        FirmwareUpdateCheckResponse, FirmwareUpdateResult,
    },
    fx::ExchangeRate,
    pairing::{PairingRequest, PairingResponse},
    scv::SecurityCheck,
    status::{DeviceStatus, EnvoyStatus},
};

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
    FirmwareFetchRequest(#[n(0)] FirmwareFetchRequest),
    #[n(4)]
    FirmwareFetchEvent(#[n(0)] FirmwareFetchEvent),
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
    #[n(12)]
    BroadcastTransaction(#[n(0)] BroadcastTransaction),
    #[n(13)]
    AccountUpdate(#[n(0)] AccountUpdate),
    #[n(14)]
    SecurityCheck(#[n(0)] SecurityCheck),
    #[n(15)]
    MagicBackupEnabledRequest(#[n(0)] MagicBackupEnabledRequest),
    #[n(16)]
    MagicBackupEnabledResponse(#[n(0)] MagicBackupEnabledResponse),
    #[n(17)]
    BackupShardRequest(#[n(0)] BackupShardRequest),
    #[n(18)]
    BackupShardResponse(#[n(0)] BackupShardResponse),
    #[n(19)]
    RestoreShardRequest(#[n(0)] RestoreShardRequest),
    #[n(20)]
    RestoreShardResponse(#[n(0)] RestoreShardResponse),
    #[n(21)]
    RawData(#[n(0)] RawData),
}
