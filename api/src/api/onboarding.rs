use crate::api::quantum_link::QuantumLink;
use {
    minicbor_derive::{Decode, Encode},
    quantum_link_macros::quantum_link,
};

#[quantum_link]
pub enum OnboardingState {
    #[n(0)]
    SecuringDevice,
    #[n(1)]
    DeviceSecured,
    #[n(2)]
    WalletCreationScreen,
    #[n(3)]
    CreatingWallet,
    #[n(4)]
    WalletCreated,
    #[n(5)]
    MagicBackupScreen,
    #[n(6)]
    CreatingMagicBackup,
    #[n(7)]
    MagicBackupCreated,
    #[n(8)]
    CreatingManualBackup,
    #[n(9)]
    CreatingKeycardBackup,
    #[n(10)]
    WritingDownSeedWords,
    #[n(11)]
    ConnectingWallet,
    #[n(12)]
    WalletConected,
    #[n(13)]
    Completed,
}
