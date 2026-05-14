use ql_rpc::Notification;

use crate::{route, Error};

rpc! {
    pub enum OnboardingState {
        SecurityChecked,
        SecurityCheckFailed,
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
        ConnectingWallet,
        WalletConnected,
        Completed,
    }
}

impl Notification for route::OnboardingStatus {
    type Error = Error;
    type Payload = OnboardingState;
}
