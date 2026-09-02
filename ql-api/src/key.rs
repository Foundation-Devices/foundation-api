pub use ql_keyos::{AppRouteKey, ServiceRouteKey};

pub mod app_id {
    use ql_keyos::AppId;

    pub const SYSTEM: AppId = AppId([0; AppId::SIZE]);
    pub const ONBOARDING: AppId = AppId::from_hex("0xdac5321775d449c11bc9c90f38067f8f");
    pub const BACKUP: AppId = AppId::from_hex("0xe19f16fcd9610bca7d026b4673f1cb06");
    pub const UPDATE: AppId = AppId::from_hex("0x6F732F75706461746500000000000000");
    pub const BITCOIN: AppId = AppId::from_hex("0x426974636f696e2057616c6c65740000");
    pub const DEBUG: AppId = AppId::from_hex("0x8ec0b4ea99704f9f973f5d7b7a3294b2");
}

pub mod service_id {
    use ql_keyos::ServiceId;

    pub const APP_STORE: ServiceId = ServiceId(1);
    pub const BACKUP: ServiceId = ServiceId(2);
    pub const BITCOIN: ServiceId = ServiceId(3);
    pub const DEBUG: ServiceId = ServiceId(4);
    pub const FIRMWARE: ServiceId = ServiceId(5);
    pub const FX: ServiceId = ServiceId(6);
    pub const SCV: ServiceId = ServiceId(7);
    pub const TIME: ServiceId = ServiceId(8);
}
