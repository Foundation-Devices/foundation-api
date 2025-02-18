use {
    minicbor_derive::{Decode, Encode},
    quantum_link_macros::QuantumLink,
};
use crate::api::quantum_link::QuantumLink;

#[derive(Clone, Encode, Decode, QuantumLink)]
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
    Completed,
}
