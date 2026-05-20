// 1. list catalog of apps (request/response)
// 2. get app by id
// 3. download version?

#[macro_use]
mod macros;

mod app_store;
mod backup;
mod benchmark;
mod bitcoin;
mod codec;
mod firmware;
mod fx;
mod onboarding;
mod scv;
mod status;
mod time;

pub use app_store::*;
pub use backup::*;
pub use benchmark::*;
pub use bitcoin::*;
pub use firmware::*;
pub use fx::*;
pub use onboarding::*;
pub use scv::*;
pub use status::*;
pub use time::*;

pub type Error = ciborium::de::Error<std::io::Error>;

pub const SERVICE_ID: ql_common::ServiceId = ql_common::ServiceId([0; 16]);

routes! {
    // app store
    ListApps = 200,
    AppDownload = 201,

    // status and presence
    DeviceStatus = 300,
    EnvoyStatus = 301,
    Timezone = 303,
    CurrentTime = 304,

    // status and presence
    PassportDetails = 402,
    PassportDetailsUpdated = 403,

    // security and onboarding
    SecurityCheck = 500,
    OnboardingStatus = 501,

    // firmware
    FirmwareUpdateCheck = 600,
    FirmwareDownload = 601,
    FirmwareInstallStatus = 602,

    // market data
    ExchangeRateUpdate = 700,
    ExchangeRateSubscription = 701,
    ExchangeRateHistory = 702,
    PassportFiatPreference = 703,
    PassportFiatPreferenceRequest = 704,

    // bitcoin and wallet
    SignPsbt = 800,
    BroadcastTransaction = 801,
    AccountUpdate = 802,
    PassportActiveSeedFingerprint = 803,
    GetPassportActiveSeedFingerprint = 804,

    // backup
    BackupShard = 900,
    RestoreShard = 901,
    EnvoyMagicBackupEnabled = 902,
    PassportMagicBackupEnabled = 903,
    PassportMagicBackupStatus = 904,
    UploadMagicBackup = 905,
    DownloadMagicBackup = 906,
    RestoreMagicBackupComplete = 907,

    // debug
    Echo = 1000,
    BytesBenchmark = 1001,
    DownloadBenchmark = 1002,
}
