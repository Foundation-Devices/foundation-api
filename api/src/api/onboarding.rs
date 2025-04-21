use {
    minicbor_derive::{Decode, Encode},
    quantum_link_macros::quantum_link,
};
use crate::api::quantum_link::QuantumLink;
use flutter_rust_bridge::frb;


#[quantum_link]
pub enum OnboardingState {
    #[n(0)]
    FirmwareUpdateScreen,
    #[n(1)]
    DownloadingUpdate,
    #[n(2)]
    ReceivingUpdate,
    #[n(3)]
    VeryfyingSignatures,
    #[n(4)]
    InstallingUpdate,
    #[n(5)]
    Rebooting,
    #[n(6)]
    FirmwareUpdated,
    #[n(7)]
    SecuringDevice,
    #[n(8)]
    DeviceSecured,
    #[n(9)]
    WalletCreationScreen,
    #[n(10)]
    CreatingWallet,
    #[n(11)]
    WalletCreated,
    #[n(12)]
    MagicBackupScreen,
    #[n(13)]
    CreatingMagicBackup,
    #[n(14)]
    MagicBackupCreated,
    #[n(15)]
    CreatingManualBackup,
    #[n(16)]
    CreatingKeycardBackup,
    #[n(17)]
    WritingDownSeedWords,
    #[n(18)]
    ConnectingWallet,
    #[n(19)]
    WalletConected,
    #[n(20)]
    Completed,
    #[n(21)]
    SecurityChecked,
    #[n(22)]
    UpdateAvailable,
    #[n(23)]
    UpdateNotAvailable,
}
