use quantum_link_macros::quantum_link;

#[quantum_link]
pub enum OnboardingState {
    #[n(0)]
    SecurityChecked,
    #[n(1)]
    SecurityCheckFailed,

    #[n(2)]
    FirmwareUpdateScreen,

    /// pin
    #[n(3)]
    SecuringDevice,
    /// pin
    #[n(4)]
    DeviceSecured,

    #[n(5)]
    WalletCreationScreen,
    #[n(6)]
    CreatingWallet,
    #[n(7)]
    WalletCreated,

    #[n(8)]
    MagicBackupScreen,
    #[n(9)]
    CreatingMagicBackup,
    #[n(10)]
    MagicBackupCreated,

    #[n(11)]
    CreatingManualBackup,
    #[n(12)]
    CreatingKeycardBackup,

    #[n(13)]
    WritingDownSeedWords,
    #[n(14)]
    ConnectingWallet,
    #[n(15)]
    WalletConected,
    #[n(16)]
    Completed,
}
