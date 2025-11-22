use quantum_link_macros::quantum_link;

use super::onboarding::OnboardingState;
use crate::{
    backup::{
        BackupShardRequest, BackupShardResponse, CreateMagicBackupEvent, CreateMagicBackupResult,
        EnvoyMagicBackupEnabledRequest, EnvoyMagicBackupEnabledResponse, PrimeMagicBackupEnabled,
        PrimeMagicBackupStatusRequest, PrimeMagicBackupStatusResponse, RestoreMagicBackupEvent,
        RestoreMagicBackupRequest, RestoreMagicBackupResult, RestoreShardRequest,
        RestoreShardResponse,
    },
    bitcoin::*,
    firmware::{
        FirmwareFetchEvent, FirmwareFetchRequest, FirmwareInstallEvent, FirmwareUpdateCheckRequest,
        FirmwareUpdateCheckResponse,
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
    #[n(1)]
    ExchangeRateHistory(ExchangeRateHistory),

    #[n(2)]
    FirmwareUpdateCheckRequest(FirmwareUpdateCheckRequest),
    #[n(3)]
    FirmwareUpdateCheckResponse(FirmwareUpdateCheckResponse),
    #[n(4)]
    FirmwareFetchRequest(FirmwareFetchRequest),
    #[n(5)]
    FirmwareFetchEvent(FirmwareFetchEvent),
    #[n(6)]
    FirmwareInstallEvent(FirmwareInstallEvent),

    #[n(7)]
    DeviceStatus(DeviceStatus),
    #[n(8)]
    EnvoyStatus(EnvoyStatus),

    #[n(9)]
    PairingRequest(PairingRequest),
    #[n(10)]
    PairingResponse(PairingResponse),

    #[n(11)]
    SecurityCheck(SecurityCheck),
    #[n(12)]
    OnboardingState(OnboardingState),

    #[n(13)]
    SignPsbt(SignPsbt),
    #[n(14)]
    BroadcastTransaction(BroadcastTransaction),
    #[n(15)]
    AccountUpdate(AccountUpdate),
    #[n(16)]
    ApplyPassphrase(ApplyPassphrase),

    #[n(17)]
    EnvoyMagicBackupEnabledRequest(EnvoyMagicBackupEnabledRequest),
    #[n(18)]
    EnvoyMagicBackupEnabledResponse(EnvoyMagicBackupEnabledResponse),

    #[n(19)]
    PrimeMagicBackupEnabled(PrimeMagicBackupEnabled),

    #[n(20)]
    PrimeMagicBackupStatusRequest(PrimeMagicBackupStatusRequest),
    #[n(21)]
    PrimeMagicBackupStatusResponse(PrimeMagicBackupStatusResponse),

    #[n(22)]
    BackupShardRequest(BackupShardRequest),
    #[n(23)]
    BackupShardResponse(BackupShardResponse),

    #[n(24)]
    RestoreShardRequest(RestoreShardRequest),
    #[n(25)]
    RestoreShardResponse(RestoreShardResponse),

    #[n(26)]
    CreateMagicBackupEvent(CreateMagicBackupEvent),
    #[n(27)]
    CreateMagicBackupResult(CreateMagicBackupResult),

    #[n(28)]
    RestoreMagicBackupRequest(RestoreMagicBackupRequest),
    #[n(29)]
    RestoreMagicBackupEvent(RestoreMagicBackupEvent),
    #[n(30)]
    RestoreMagicBackupResult(RestoreMagicBackupResult),
}
