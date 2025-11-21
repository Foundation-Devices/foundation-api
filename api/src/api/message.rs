use quantum_link_macros::quantum_link;

use super::onboarding::OnboardingState;
use crate::{
    api::raw::RawData,
    backup::{
        BackupShardRequest, BackupShardResponse, CreateMagicBackupEvent, CreateMagicBackupResult,
        EnvoyMagicBackupEnabledRequest, EnvoyMagicBackupEnabledResponse, PrimeMagicBackupEnabled,
        PrimeMagicBackupStatusRequest, PrimeMagicBackupStatusResponse, RestoreMagicBackupEvent,
        RestoreMagicBackupRequest, RestoreMagicBackupResult, RestoreShardRequest,
        RestoreShardResponse,
    },
    bitcoin::*,
    firmware::{
        FirmwareFetchEvent, FirmwareFetchRequest, FirmwareUpdateCheckRequest,
        FirmwareUpdateCheckResponse, FirmwareUpdateResult,
    },
    fx::{ExchangeRate, ExchangeRateHistory},
    pairing::{PairingRequest, PairingResponse},
    scv::SecurityCheck,
    status::{DeviceStatus, EnvoyStatus},
};

#[quantum_link]
pub struct EnvoyMessage {
    #[n(0)]
    pub message: QuantumLinkMessage,
    #[n(1)]
    pub timestamp: u32,
}

#[quantum_link]
pub struct PassportMessage {
    #[n(0)]
    pub message: QuantumLinkMessage,
    #[n(1)]
    pub status: DeviceStatus,
}

#[quantum_link]
pub enum QuantumLinkMessage {
    #[n(0)]
    ExchangeRate(ExchangeRate),
    #[n(26)]
    ExchangeRateHistory(ExchangeRateHistory),

    #[n(1)]
    FirmwareUpdateCheckRequest(FirmwareUpdateCheckRequest),
    #[n(2)]
    FirmwareUpdateCheckResponse(FirmwareUpdateCheckResponse),
    #[n(3)]
    FirmwareFetchRequest(FirmwareFetchRequest),
    #[n(4)]
    FirmwareFetchEvent(FirmwareFetchEvent),
    #[n(5)]
    FirmwareUpdateResult(FirmwareUpdateResult),
    #[n(6)]
    DeviceStatus(DeviceStatus),
    #[n(7)]
    EnvoyStatus(EnvoyStatus),
    #[n(8)]
    PairingRequest(PairingRequest),
    #[n(9)]
    PairingResponse(PairingResponse),
    #[n(10)]
    OnboardingState(OnboardingState),
    #[n(11)]
    SignPsbt(SignPsbt),
    #[n(12)]
    BroadcastTransaction(BroadcastTransaction),
    #[n(13)]
    AccountUpdate(AccountUpdate),
    #[n(27)]
    ApplyPassphrase(ApplyPassphrase),
    #[n(14)]
    SecurityCheck(SecurityCheck),

    #[n(15)]
    EnvoyMagicBackupEnabledRequest(EnvoyMagicBackupEnabledRequest),
    #[n(16)]
    EnvoyMagicBackupEnabledResponse(EnvoyMagicBackupEnabledResponse),

    #[n(28)]
    PrimeMagicBackupEnabled(PrimeMagicBackupEnabled),

    #[n(29)]
    PrimeMagicBackupStatusRequest(PrimeMagicBackupStatusRequest),
    #[n(30)]
    PrimeMagicBackupStatusResponse(PrimeMagicBackupStatusResponse),

    #[n(17)]
    BackupShardRequest(BackupShardRequest),
    #[n(18)]
    BackupShardResponse(BackupShardResponse),

    #[n(19)]
    RestoreShardRequest(RestoreShardRequest),
    #[n(20)]
    RestoreShardResponse(RestoreShardResponse),

    #[n(21)]
    CreateMagicBackupEvent(CreateMagicBackupEvent),
    #[n(22)]
    CreateMagicBackupResult(CreateMagicBackupResult),

    #[n(23)]
    RestoreMagicBackupRequest(RestoreMagicBackupRequest),
    #[n(24)]
    RestoreMagicBackupEvent(RestoreMagicBackupEvent),
    #[n(25)]
    RestoreMagicBackupResult(RestoreMagicBackupResult),

    #[n(100)]
    RawData(RawData),
}
