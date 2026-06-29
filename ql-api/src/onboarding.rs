use ql_rpc::Subscription;

use crate::{Empty, Error};

// APP ROUTES

app_routes! {
    crate::app_id::ONBOARDING => {
        SubscribeOnboardingStatus: Subscription = 1,
    }
}

rpc! {
    pub enum OnboardingState {
        FirmwareUpdateScreen,
        SecuringDevice,
        DeviceSecured,
        WalletCreationScreen,
        CreatingWallet,
        WalletCreated,
        MagicBackupScreen,
        CreatingMagicBackup,
        MagicBackupCreated,
        CreatingManualBackup,
        CreatingKeycardBackup,
        WritingDownSeedWords,
        Completed,
    }
}

impl Subscription for SubscribeOnboardingStatus {
    type Error = Error;
    type Request = Empty;
    type Event = OnboardingState;
}

// SERVICE ROUTES
