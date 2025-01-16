use {
    crate::api::QuantumLinkMessage,
    minicbor_derive::{Decode, Encode},
};

#[derive(Clone, Encode, Decode)]
pub enum OnboardingState {
    #[n(0)]
    SecuringDevice,
    #[n(1)]
    CreatingWallet,
    #[n(2)]
    CreatingMagicBackup,
    #[n(3)]
    CreatingManualBackup,
    #[n(4)]
    CreatingKeycardBackup,
    #[n(5)]
    WritingDownSeedWords,
    #[n(6)]
    ConnectingWallet,
    #[n(7)]
    Completed
}

